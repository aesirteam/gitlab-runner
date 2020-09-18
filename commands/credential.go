package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"gitlab.com/gitlab-org/gitlab-runner/common"
	"io/ioutil"
	api "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"net/http"
	"strings"
)
type CredentialCommand struct {
	//Client      *kubernetes.Clientset
	Name 	    string `long:"name" description:"Secret name by kubernetes"`
	Namespace	string `long:"namespace" env:"KUBERNETES_NAMESPACE" description:"Namespace by Kubernetes"`
	Type        string `long:"type" description:"Registry type: docker/npm"`
	Registry	string `long:"registry" description:"Registry url"`
	Username	string `long:"username" description:"Registry username"`
	Password  	string `long:"password" description:"Registry password"`
}

func (c *CredentialCommand) GetNpmLoginContent() (*string, error) {
	url := c.Registry + `/-/user/org.couchdb.user:` + c.Username
	reqBody := bytes.NewBuffer([]byte(`{"name":"`+ c.Username +`","password":"`+ c.Password +`"}`))

	req, _ := http.NewRequest("PUT", url, reqBody)
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type","application/vnd.npm.install-v1+json")
	req.Header.Set("Accept","application/vnd.npm.install-v1+json")

	httpClient := &http.Client{}
	resp, _ := httpClient.Do(req)
	defer resp.Body.Close()

	if resp.StatusCode == 201 {
		respBody, _ := ioutil.ReadAll(resp.Body)
		var data struct {
			Status	string `json:"ok"`
			Token	string `json:"token"`
		}

		err := json.Unmarshal(respBody, &data)
		if err != nil {
			return nil, err
		}

		npmrc := strings.Join([]string{
			`unsafe-perm=true`,
			`registry=` + c.Registry,
			strings.Replace(c.Registry, req.URL.Scheme + `:`, "",1) + `/:_authToken="` + data.Token + `"`,
		},"\n")
		//logrus.Println(npmrc)

		return &npmrc, nil
	}
	
	return nil, errors.New(resp.Status)
}

func (c *CredentialCommand) GetDockerSecret() (*api.Secret, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(c.Username + ":" + c.Password))
	dockerCfgContent := []byte(`{"auths": {"` + c.Registry + `": {"auth": "` + auth + `"}}}`)
	//logrus.Println(string(dockerCfgContent))

	secret := api.Secret{}
	secret.Name = c.Name
	secret.Namespace = c.Namespace
	secret.Type = api.SecretTypeDockerConfigJson
	secret.StringData = map[string]string{}
	secret.StringData[api.DockerConfigJsonKey] = string(dockerCfgContent)
	secret.StringData["config.json"] = secret.StringData[api.DockerConfigJsonKey]
	//_json, _ := json.Marshal(secret)
	//logrus.Println(string(_json))

	return &secret, nil
}

func (c *CredentialCommand) GetNpmSecret() (*api.Secret, error) {
	npmrc, err := c.GetNpmLoginContent()
	if err != nil {
		return nil, err
	}

	secret := api.Secret{}
	secret.Name = c.Name
	secret.Namespace = c.Namespace
	secret.Type = api.SecretTypeOpaque
	secret.StringData = map[string]string{}
	secret.StringData[".npmrc"] = *npmrc
	//_json, _ := json.Marshal(secret)
	//logrus.Println(string(_json))

	return &secret, nil
}

func (c *CredentialCommand) Execute(context *cli.Context) {
	cfg, err := restclient.InClusterConfig()
	if err != nil {
		logrus.Fatalln(err)
	}

	var secret *api.Secret
	if c.Type == "npm" {
		secret, err = c.GetNpmSecret()
	} else {
		secret, err = c.GetDockerSecret()
	}

	if err != nil {
		logrus.Fatalln(err)
	}

	client := kubernetes.NewForConfigOrDie(cfg)

	_, err = client.CoreV1().Secrets(c.Namespace).Update(secret)
	if err != nil {
		_, err = client.CoreV1().Secrets(c.Namespace).Create(secret)
	}

	if err != nil {
		logrus.Fatalln(err)
	}

	logrus.Println(`Kubernetes secret "` + c.Name + `" created successfully.`)
}

func init() {
	common.RegisterCommand2("credential", "create docker credential", &CredentialCommand{
		//Client: kubernetes.NewForConfigOrDie(&restclient.Config{
		//	Host: os.Getenv("KUBERNETES_HOST"),
		//	BearerTokenFile: os.Getenv("KUBERNETES_BEARER_FILE"),
		//	TLSClientConfig: restclient.TLSClientConfig{
		//		CAFile: os.Getenv("KUBERNETES_CA_FILE"),
		//	},
		//	UserAgent: common.AppVersion.UserAgent(),
		//}),
	})
}