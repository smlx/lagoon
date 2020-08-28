package exec

import (
	"io"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/deprecated/scheme"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// Client is a k8s pod exec client.
type Client struct {
	config    *rest.Config
	clientset *kubernetes.Clientset
}

// New creates a new kubernetes api client.
func New() (*Client, error) {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return &Client{
		config:    config,
		clientset: clientset,
	}, nil
}

// Exec joins the given streams to the command or, if command is empty, to a
// shell running in the given pod.
func (c *Client) Exec(pod, namespace string, command []string, stdio io.ReadWriter, stderr io.Writer) error {
	// check the command.
	// if there isn't one, the user wants an interactive terminal.
	var tty bool
	if len(command) == 0 {
		command = []string{"sh"}
		tty = true
	}
	// construct the request
	req := c.clientset.CoreV1().RESTClient().Post().Resource("pods").
		Name(pod).Namespace(namespace).SubResource("exec")
	req.VersionedParams(
		&v1.PodExecOptions{
			Command: command,
			Stdin:   true,
			Stdout:  true,
			Stderr:  true,
			TTY:     tty,
		},
		scheme.ParameterCodec,
	)
	// construct the executor
	exec, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return err
	}
	// execute the command
	return exec.Stream(remotecommand.StreamOptions{
		Stdin:  stdio,
		Stdout: stdio,
		Stderr: stderr,
	})
}
