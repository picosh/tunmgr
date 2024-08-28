package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/antoniomika/syncmap"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type sliceFlags []string

func (s *sliceFlags) String() string {
	return fmt.Sprintf("%+v", []string(*s))
}

func (s *sliceFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type TunHandler struct {
	Listener   net.Listener
	RemoteAddr string
	LocalAddr  string
	Done       chan struct{}
}

type TunMgr struct {
	DockerClient *client.Client
	SSHClient    *ssh.Client
	Tunnels      *syncmap.Map[string, *syncmap.Map[string, *TunHandler]]
}

func (m *TunMgr) RemoveTunnels(tunnelID string) error {
	tunHandlers, ok := m.Tunnels.Load(tunnelID)
	if !ok {
		return fmt.Errorf("unable to find tunnel: %s", tunnelID)
	}

	toDelete := []string{}

	logger := slog.With(
		slog.String("tunnel_id", tunnelID),
	)

	tunHandlers.Range(func(rAddr string, handler *TunHandler) bool {
		innerLogger := logger.With(
			slog.String("remote_addr", rAddr),
		)

		innerLogger.Info(
			"Closing tunnel",
		)
		close(handler.Done)

		toDelete = append(toDelete, rAddr)

		remoteHost, remotePort, err := net.SplitHostPort(rAddr)
		if err != nil {
			innerLogger.Error(
				"Unable to parse remote addr",
				slog.Any("error", err),
			)
			return false
		}

		remotePortInt, err := strconv.Atoi(remotePort)
		if err != nil {
			innerLogger.Error(
				"Unable to parse remote port",
				slog.Any("error", err),
			)
			return false
		}

		forwardMessage := channelForwardMsg{
			addr:  remoteHost,
			rport: uint32(remotePortInt),
		}

		ok, _, err := m.SSHClient.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(&forwardMessage))
		if err != nil {
			innerLogger.Error(
				"Error sending cancel request",
				slog.Any("error", err),
			)
			return false
		}

		if !ok {
			innerLogger.Error(
				"Request to cancel rejected by peer",
				slog.Any("error", err),
			)
		}

		return true
	})

	for _, rAddr := range toDelete {
		tunHandlers.Delete(rAddr)
	}

	m.Tunnels.Delete(tunnelID)

	return nil
}

type channelForwardMsg struct {
	addr  string
	rport uint32
}

type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func (m *TunMgr) AddTunnel(tunnelID string, remoteAddr string, localAddr string) (string, error) {
	tunHandlers, _ := m.Tunnels.LoadOrStore(tunnelID, syncmap.New[string, *TunHandler]())

	var remoteHost string
	var remotePort string
	var err error

	if strings.Contains(remoteAddr, ":") {
		remoteHost, remotePort, err = net.SplitHostPort(remoteAddr)
		if err != nil {
			return "", err
		}
	} else {
		remoteHost = "localhost"
		remotePort = remoteAddr
	}

	remotePortInt, err := strconv.Atoi(remotePort)
	if err != nil {
		return "", err
	}

	forwardMessage := channelForwardMsg{
		addr:  remoteHost,
		rport: uint32(remotePortInt),
	}

	ok, resp, err := m.SSHClient.SendRequest("tcpip-forward", true, ssh.Marshal(&forwardMessage))
	if err != nil {
		return "", err
	}

	if !ok {
		return "", errors.New("ssh: tcpip-forward request denied by peer")
	}

	// If the original port was 0, then the remote side will
	// supply a real port number in the response.
	if remotePortInt == 0 {
		var p struct {
			Port uint32
		}
		if err := ssh.Unmarshal(resp, &p); err != nil {
			return "", err
		}
		remotePortInt = int(p.Port)
	}

	remoteAddr = fmt.Sprintf("%s:%d", remoteHost, remotePortInt)

	handler := &TunHandler{
		RemoteAddr: remoteAddr,
		LocalAddr:  localAddr,
		Done:       make(chan struct{}),
	}

	tunHandlers.Store(remoteAddr, handler)

	return remoteAddr, err
}

func (m *TunMgr) WatchDog() {
	err := m.SSHClient.Wait()
	slog.Error("SSH Connection closed, killing program", slog.Any("error", err))
	panic(err)
}

func (m *TunMgr) HandleLogs() {
	session, err := m.SSHClient.NewSession()
	if err != nil {
		slog.Error("Unable to handle logs, setup session failed", slog.Any("error", err))
		return
	}

	r, w := io.Pipe()

	session.Stderr = w
	session.Stdout = w

	err = session.Shell()
	if err != nil {
		slog.Error("Unable to handle logs, run shell failed", slog.Any("error", err))
		return
	}

	_, err = io.Copy(os.Stdout, r)
	if err != nil {
		slog.Error("Unable to handle logs, copy to stdout failed", slog.Any("error", err))
		return
	}
}

func (m *TunMgr) HandleChannels() {
	for ch := range m.SSHClient.HandleChannelOpen("forwarded-tcpip") {
		logger := slog.With(
			slog.String("channel_type", ch.ChannelType()),
			slog.String("extra_data", string(ch.ExtraData())),
		)

		logger.Debug("Received channel open")

		switch channelType := ch.ChannelType(); channelType {
		case "forwarded-tcpip":
			var payload forwardedTCPPayload
			if err := ssh.Unmarshal(ch.ExtraData(), &payload); err != nil {
				logger.Error(
					"Unable to parse forwarded-tcpip payload",
					slog.Any("error", err),
				)
				ch.Reject(ssh.ConnectionFailed, "could not parse forwarded-tcpip payload: "+err.Error())
				continue
			}

			remoteAddr := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)

			failed := true

			logger.Debug("About to iterate")

			m.Tunnels.Range(func(tunnelID string, tunHandlers *syncmap.Map[string, *TunHandler]) bool {
				tunLogger := logger.With(
					slog.String("tunnel_id", tunnelID),
					slog.String("remote_addr", remoteAddr),
				)

				tunLogger.Debug("run iteration")

				handler, ok := tunHandlers.Load(remoteAddr)
				tunLogger.Debug("handler", slog.Any("handler", handler), slog.Bool("ok", ok))
				if !ok {
					tunLogger.Debug("Unable to find handler")
					return true
				}

				failed = false

				handlerLogger := tunLogger.With(
					slog.String("local_addr", handler.LocalAddr),
				)

				handlerLogger.Debug("About to start goroutine to accept")

				go func(ch ssh.NewChannel) {
					remoteConn, reqs, acceptErr := ch.Accept()
					if acceptErr != nil {
						handlerLogger.Error(
							"Error accepting connection from listener",
							slog.Any("error", acceptErr),
						)
						return
					}

					go ssh.DiscardRequests(reqs)

					go func() {
						defer remoteConn.Close()

						localConn, localErr := net.Dial("tcp", handler.LocalAddr)
						if localErr != nil {
							handlerLogger.Error(
								"Error starting local conn",
								slog.String("local_addr", handler.LocalAddr),
								slog.Any("error", localErr),
							)
							return
						}

						defer localConn.Close()

						wg := &sync.WaitGroup{}
						wg.Add(2)

						go func() {
							handlerLogger.Debug("Start copy to remote")
							defer wg.Done()
							n, err := io.Copy(remoteConn, localConn)
							handlerLogger.Debug(
								"Copy to remote conn",
								slog.Int64("n", n),
								slog.Any("error", err),
							)
							remoteConn.CloseWrite()
						}()

						go func() {
							handlerLogger.Debug("Start copy to local")
							defer wg.Done()
							n, err := io.Copy(localConn, remoteConn)
							handlerLogger.Debug(
								"Copy to local conn",
								slog.Int64("n", n),
								slog.Any("error", err),
							)
							if cw, ok := localConn.(interface{ CloseWrite() error }); ok {
								cw.CloseWrite()
							}
						}()

						wg.Wait()
					}()
				}(ch)

				return !ok
			})

			if failed {
				ch.Reject(ssh.ConnectionFailed, "unable to find tunnel")
			}
		}
	}
}

func NewTunMgr(dockerClient *client.Client, sshClient *ssh.Client) *TunMgr {
	return &TunMgr{
		DockerClient: dockerClient,
		SSHClient:    sshClient,
		Tunnels:      syncmap.New[string, *syncmap.Map[string, *TunHandler]](),
	}
}

func createDockerClient() *client.Client {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		slog.Error(
			"Unable to create docker client",
			slog.Any("error", err),
		)
		panic(err)
	}

	return dockerClient
}

func createSSHClient(remoteHost string, keyLocation string, keyPassphrase string, remoteHostname string, remoteUser string) *ssh.Client {
	if !strings.Contains(remoteHost, ":") {
		remoteHost += ":22"
	}

	rawConn, err := net.Dial("tcp", remoteHost)
	if err != nil {
		slog.Error(
			"Unable to create ssh client, tcp connection not established",
			slog.Any("error", err),
		)
		panic(err)
	}

	keyPath, err := filepath.Abs(keyLocation)
	if err != nil {
		slog.Error(
			"Unable to create ssh client, cannot find key file",
			slog.Any("error", err),
		)
		panic(err)
	}

	f, err := os.Open(keyPath)
	if err != nil {
		slog.Error(
			"Unable to create ssh client, unable to open key",
			slog.Any("error", err),
		)
		panic(err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		slog.Error(
			"Unable to create ssh client, unable to read key",
			slog.Any("error", err),
		)
		panic(err)
	}

	var signer ssh.Signer

	if keyPassphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(keyPassphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(data)
	}

	if err != nil {
		slog.Error(
			"Unable to create ssh client, unable to parse key",
			slog.Any("error", err),
		)
		panic(err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(rawConn, remoteHostname, &ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            remoteUser,
	})
	if err != nil {
		slog.Error(
			"Unable to create ssh client, unable to create client conn",
			slog.Any("error", err),
		)
		panic(err)
	}

	sshClient := ssh.NewClient(sshConn, chans, reqs)

	return sshClient
}

func handleContainerStart(tunMgr *TunMgr, logger *slog.Logger, tunnelID string, networks []string) error {
	containerInfo, err := tunMgr.DockerClient.ContainerInspect(context.Background(), tunnelID)
	if err != nil {
		logger.Error(
			"Unable to inspect container info for tunnel",
			slog.Any("error", err),
		)
		return err
	}

	logger.Debug(
		"Container info",
		slog.Any("container_info", containerInfo),
	)

	dnsNames := []string{containerInfo.ID[0:12], strings.TrimPrefix(containerInfo.Name, "/")}

	logger.Debug(
		"Pre DNS Names",
		slog.Any("dns_names", dnsNames),
	)

	logger.Debug(
		"Networks",
		slog.Any("networks", networks),
		slog.Any("container_networks", maps.Keys(containerInfo.NetworkSettings.Networks)),
	)

	logger.Debug(
		"Pre Exposed Ports",
		slog.Any("exposed_ports", containerInfo.Config.ExposedPorts),
	)

	exposedPorts := map[int]int{}
	for port := range containerInfo.Config.ExposedPorts {
		exposedPorts[port.Int()] = port.Int()
	}

	for netw := range maps.Keys(containerInfo.NetworkSettings.Networks) {
		if slices.Contains(networks, strings.ToLower(strings.TrimSpace(netw))) {
			if labelNames, ok := containerInfo.Config.Labels["tunmgr.names"]; ok {
				splitLabelNames := strings.Split(labelNames, ",")
				for k, v := range splitLabelNames {
					splitLabelNames[k] = strings.TrimSpace(v)
				}
				dnsNames = splitLabelNames
				slices.Sort(dnsNames)
			} else {
				dnsNames = append(dnsNames, containerInfo.NetworkSettings.Networks[netw].DNSNames...)
				slices.Sort(dnsNames)
				dnsNames = slices.Compact(dnsNames)
			}

			logger.Debug(
				"DNS Names",
				slog.Any("dns_names", dnsNames),
			)

			if labelPorts, ok := containerInfo.Config.Labels["tunmgr.ports"]; ok {
				labelExposedPorts := map[int]int{}
				splitLabelPorts := strings.Split(labelPorts, ",")
				for _, v := range splitLabelPorts {
					splitPort := strings.SplitN(v, ":", 2)
					if len(splitPort) != 2 {
						logger.Debug("Unable to split port into remote:local", slog.Any("label_port", v))
						continue
					}
					remotePort, err := strconv.Atoi(splitPort[0])
					if err != nil {
						logger.Debug("Unable to parse remote port", slog.Any("label_port", v), slog.Any("error", err))
						continue
					}

					localPort, err := strconv.Atoi(splitPort[1])
					if err != nil {
						logger.Debug("Unable to parse local port", slog.Any("label_port", v), slog.Any("error", err))
						continue
					}

					labelExposedPorts[remotePort] = localPort
				}
				exposedPorts = labelExposedPorts
			}

			logger.Debug(
				"Exposed Ports",
				slog.Any("exposed_ports", exposedPorts),
			)

			for remotePort, localPort := range exposedPorts {
				for _, dnsName := range dnsNames {
					var tunnelRemote string

					if dnsName != "" {
						tunnelRemote = fmt.Sprintf("%s:%d", dnsName, remotePort)
					} else {
						tunnelRemote = fmt.Sprintf("%d", remotePort)
					}

					tunnelLocal := fmt.Sprintf("%s:%d", containerInfo.NetworkSettings.Networks[netw].IPAddress, localPort)

					logger.Info(
						"Adding tunnel",
						slog.String("remote", tunnelRemote),
						slog.String("local", tunnelLocal),
					)

					remoteAddr, err := tunMgr.AddTunnel(containerInfo.ID, tunnelRemote, tunnelLocal)
					if err != nil {
						logger.Error(
							"Unable to start tunnel",
							slog.String("remote", tunnelRemote),
							slog.String("local", tunnelLocal),
							slog.Any("error", err),
						)
					}

					logger.Debug(
						"Remote addr",
						slog.String("remote_addr", remoteAddr),
					)
				}
			}
			break
		}
	}

	return nil
}

func main() {
	logLevelFlag := flag.String("log-level", "info", "Log level to set for the logger. Can be debug, warn, error, or info")
	networksFlag := flag.String("networks", "", "A comma separated list of networks to listen to events for")
	remoteHostFlag := flag.String("remote-host", "tuns.sh", "The remote host to connect to in the format of host:port")
	remoteHostnameFlag := flag.String("remote-hostname", "tuns.sh", "The remote hostname to verify the host key")
	remoteUserFlag := flag.String("remote-user", "", "The remote user to connect as")
	keyLocationFlag := flag.String("remote-key-location", "/key", "The location on the filesystem of where to access the ssh key")
	keyPassphraseFlag := flag.String("remote-key-passphrase", "", "The passphrase for an encrypted ssh key")

	var tunnels sliceFlags

	flag.Var(&tunnels, "tunnel", "Tunnel to initialize on setup. Can be provided multiple times, in the format of a -R tunnel for SSH.")

	dockerEvents := flag.Bool("docker-events", true, "Whether or not to use docker events for setting up tunnels")
	remoteLogs := flag.Bool("remote-logs", true, "Whether or not to print logs from the remote tunnels")

	flag.Parse()

	var rootLoggerLevel slog.Level

	switch strings.ToLower(*logLevelFlag) {
	case "debug":
		rootLoggerLevel = slog.LevelDebug
	case "warn":
		rootLoggerLevel = slog.LevelWarn
	case "error":
		rootLoggerLevel = slog.LevelError
	default:
		rootLoggerLevel = slog.LevelInfo
	}

	rootLogger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: rootLoggerLevel,
	}))

	slog.SetDefault(rootLogger)

	var dockerClient *client.Client
	networks := []string{}

	if *dockerEvents {
		dockerClient = createDockerClient()
		defer dockerClient.Close()

		networksToCheck := strings.TrimSpace(*networksFlag)
		if networksToCheck == "" {
			hostname, err := os.Hostname()
			if err != nil || hostname == "" {
				rootLogger.Error(
					"Unable to get hostname",
					slog.Any("error", err),
				)
			} else {
				info, err := dockerClient.ContainerInspect(context.Background(), hostname)
				if err != nil {
					rootLogger.Error(
						"Unable to find networks. Please provide a list to monitor",
						slog.Any("error", err),
					)
					panic(err)
				}

				for netw := range maps.Keys(info.NetworkSettings.Networks) {
					networks = append(networks, strings.ToLower(strings.TrimSpace(netw)))
				}
			}
		} else {
			for _, netw := range strings.Split(networksToCheck, ",") {
				networks = append(networks, strings.ToLower(strings.TrimSpace(netw)))
			}
		}
	}

	sshClient := createSSHClient(*remoteHostFlag, *keyLocationFlag, *keyPassphraseFlag, *remoteHostnameFlag, *remoteUserFlag)
	defer sshClient.Close()

	loggerArgs := []any{
		slog.String("ssh", sshClient.RemoteAddr().String()),
		slog.String("ssh_user", sshClient.User()),
	}

	if dockerClient != nil {
		loggerArgs = append(loggerArgs, slog.String("docker", dockerClient.DaemonHost()),
			slog.String("docker_version", dockerClient.ClientVersion()))
	}

	rootLogger.Info(
		"Started tunmgr",
		loggerArgs...,
	)

	tunMgr := NewTunMgr(dockerClient, sshClient)

	go tunMgr.WatchDog()

	if *remoteLogs {
		go tunMgr.HandleLogs()
	}

	go tunMgr.HandleChannels()

	go func() {
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
		})

		err := http.ListenAndServe("localhost:8080", nil)
		if err != nil {
			rootLogger.Error("error with http server", slog.Any("error", err))
		}
	}()

	for _, tunnel := range tunnels {
		tunnelInfo := strings.Split(tunnel, ":")

		if len(tunnelInfo) < 3 {
			continue
		}

		tunnelRemote := tunnelInfo[0]
		if len(tunnelInfo) == 4 {
			tunnelRemote += fmt.Sprintf(":%s", tunnelInfo[1])
		}

		tunnelLocal := fmt.Sprintf("%s:%s", tunnelInfo[len(tunnelInfo)-2], tunnelInfo[len(tunnelInfo)-1])

		rootLogger.Info(
			"Adding tunnel",
			slog.String("remote", tunnelRemote),
			slog.String("local", tunnelLocal),
		)

		remoteAddr, err := tunMgr.AddTunnel(uuid.New().String(), tunnelRemote, tunnelLocal)
		if err != nil {
			rootLogger.Error(
				"Unable to start tunnel",
				slog.String("remote", tunnelRemote),
				slog.String("local", tunnelLocal),
				slog.Any("error", err),
			)
		}

		rootLogger.Debug(
			"Remote addr",
			slog.String("remote_addr", remoteAddr),
		)
	}

	if dockerClient != nil {
		go func() {
			eventCtx, cancelEventCtx := context.WithCancel(context.Background())

			clientEvents, errs := dockerClient.Events(eventCtx, events.ListOptions{})

			containers, err := dockerClient.ContainerList(context.Background(), container.ListOptions{})
			if err != nil {
				rootLogger.Error(
					"unable to list container from docker",
					slog.Any("error", err),
				)
			}

			for _, container := range containers {
				err := handleContainerStart(tunMgr, rootLogger, container.ID, networks)
				if err != nil {
					rootLogger.Error(
						"Unable to add tunnels for container",
						slog.String("tunnel_id", container.ID),
						slog.Any("error", err),
						slog.Any("container_data", container),
					)
					break
				}
			}

			for {
				select {
				case event := <-clientEvents:
					switch event.Type {
					case events.ContainerEventType:
						logger := slog.With(
							slog.String("event", string(event.Action)),
							slog.String("tunnel_id", event.Actor.ID),
						)
						switch event.Action {
						case events.ActionStart:
							logger.Info("Received start")
							err := handleContainerStart(tunMgr, logger, event.Actor.ID, networks)
							if err != nil {
								logger.Error(
									"Unable to add tunnels for container",
									slog.Any("error", err),
								)
								break
							}
						case events.ActionDie:
							logger.Info("Received die")
							err := tunMgr.RemoveTunnels(event.Actor.ID)
							if err != nil {
								logger.Error(
									"Unable to remove tunnels for container",
									slog.Any("error", err),
								)
								break
							}
						default:
							logger.Debug(
								"Unhandled container action",
								slog.Any("event_data", event),
							)
						}
					default:
						slog.Debug(
							"Unhandled daemon event",
							slog.Any("event_data", event),
						)
					}
				case err := <-errs:
					cancelEventCtx()
					slog.Error(
						"Error receiving events from daemon",
						slog.Any("error", err),
					)
					panic(err)
				}
			}
		}()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for s := range c {
		slog.Info("Signal recieved. Exiting", slog.Any("signal", s))
		break
	}
}
