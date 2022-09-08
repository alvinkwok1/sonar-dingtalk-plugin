package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
)

const (
	PullRequest string = "PULL_REQUEST"
	MetricKeys  string = "alert_status,bugs,code_smells,vulnerabilities,coverage,duplicated_lines_density," +
		"new_bugs,new_code_smells,new_vulnerabilities,new_coverage,new_duplicated_lines_density"
)

type command struct {
	host        string // 需要监听的主机
	port        int    // 需要监听的端口
	multiBranch bool   //是否使用了多分支插件
}

type sonarScanResult struct {
	accessToken string
	sonarToken  string
	serverUrl   string
	projectName string // 项目名称
	projectKey  string // 项目key
	branchName  string // 分支名称或者是PR/MR的信息
	branchUrl   string // 分支扫描结果地址
	branchType  string // 分支类型，PULL_REQUEST
	projectUrl  string // 项目地址

	// 当前仓库的情况 (PR的时候不需要关注g)
	bugs            string // bug数量
	codeSmells      string // 异味数量
	vulnerabilities string // 漏洞数量
	coverage        string // 代码覆盖率
	duplicatedLines string // 重复代码行

	// 新代码扫描情况
	alterStatus         string // 扫描结果
	new_bugs            string // 新增 	bug数量
	new_codeSemlls      string // 新增异味数量
	new_coverage        string //最新代码覆盖率
	new_duplicatedLines string // 最新代码覆盖率
	new_vulnerabilities string // 新增漏洞数量s
}

var programCommand *command = nil

// bind program command
func initCommand() {
	programCommand = &command{}
	flag.StringVar(&programCommand.host, "h", "0.0.0.0", "监听地址")
	flag.IntVar(&programCommand.port, "p", 9010, "监听端口")
	flag.BoolVar(&programCommand.multiBranch, "mb", false, "Sonarqube 是否支持多分支,默认为社区版不支持，如果已经安装了社区版多分支插件请选择该选项")
	flag.Parse()
}

func writeError(w http.ResponseWriter, msg string) error {
	_, err := fmt.Fprintf(w, msg)
	return err
}

func getMapValue(c interface{}, key string) string {
	if c != nil {
		tempC := c.(map[string]interface{})
		tempValue := tempC[key]
		if tempValue != nil {
			return tempValue.(string)
		}
	}
	return ""
}

func parseWebhook(s *sonarScanResult, r *http.Request) error {
	err := r.ParseForm()
	if err != nil {
		log.Println("解析参数错误")
		return err
	}
	// 解析URL参数
	s.accessToken = r.Form.Get("access_token")
	s.sonarToken = r.Form.Get("sonar_token")
	if s.accessToken == "" {
		return errors.New("access_token不能为空")
	}
	// 做json转换
	sonarRsp := make(map[string]interface{})
	if err = json.NewDecoder(r.Body).Decode(&sonarRsp); err != nil {
		r.Body.Close()
		return err
	}
	// sonar地址
	s.serverUrl = sonarRsp["serverUrl"].(string)
	// 解析项目信息
	s.projectName = getMapValue(sonarRsp["project"], "name")
	s.projectKey = getMapValue(sonarRsp["project"], "key")
	// 解析分支信息
	s.branchName = getMapValue(sonarRsp["branch"], "name")
	s.branchUrl = getMapValue(sonarRsp["branch"], "url")
	s.branchType = getMapValue(sonarRsp["branch"], "type")
	return nil
}

func findMeasures(measures []interface{}, key string) string {
	for _, v := range measures {
		tempValue := v.(map[string]interface{})
		// 获取key
		tempKey := tempValue["metric"].(string)
		if key == tempKey {
			// 尝试获取value
			val := tempValue["value"]
			if val != nil {
				return tempValue["value"].(string)
			} else {
				return tempValue["period"].(map[string]interface{})["value"].(string)
			}
		}
	}
	return ""
}

func parseMeasureResponse(s *sonarScanResult, measuresRsp *http.Response) error {
	resp := make(map[string]interface{})
	if err := json.NewDecoder(measuresRsp.Body).Decode(&resp); err != nil {
		measuresRsp.Body.Close()
		return err
	}

	component := resp["component"].(map[string]interface{})
	measures := component["measures"].([]interface{})
	s.alterStatus = findMeasures(measures, "alert_status")
	s.bugs = findMeasures(measures, "bugs")
	s.codeSmells = findMeasures(measures, "code_smells")
	s.vulnerabilities = findMeasures(measures, "vulnerabilities")
	s.coverage = findMeasures(measures, "coverage")
	s.duplicatedLines = findMeasures(measures, "duplicated_lines_density")
	// 查找新代码数据
	s.new_bugs = findMeasures(measures, "new_bugs")
	s.new_codeSemlls = findMeasures(measures, "new_code_smells")
	s.new_vulnerabilities = findMeasures(measures, "new_vulnerabilities")
	s.new_coverage = findMeasures(measures, "new_coverage")
	s.new_duplicatedLines = findMeasures(measures, "new_duplicated_lines_density")
	return nil
}

// 通过API接口请求本次提交的相关信息
func requestScanResult(s *sonarScanResult) error {
	baseUrl := fmt.Sprintf("%s/api/measures/component?additionalFields=metrics&component=%s&metricKeys=%s",
		s.serverUrl, s.projectKey, MetricKeys)
	// 如果是PR请求的时候需要拼接上pr请求ID
	if s.branchType == PullRequest && s.branchName != "" {
		baseUrl = fmt.Sprintf("%s&pullRequest=%s", baseUrl, s.branchName)
	} else if s.branchName != "" {
		baseUrl = fmt.Sprintf("%s&branch=%s", baseUrl, s.branchName)
	}
	// create http client
	httpClient := &http.Client{
		Transport: &http.Transport{
			// 设置代理 HTTPS_PROXY
			Proxy: http.ProxyFromEnvironment,
		},
	}
	// 创建请求
	req, _ := http.NewRequest("GET", baseUrl, nil)
	if s.sonarToken != "" {
		req.SetBasicAuth(s.sonarToken, "")
	}
	// 请求扫描结果
	measuresRsp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	// 解析扫描结果
	err = parseMeasureResponse(s, measuresRsp)
	if err != nil {
		return err
	}
	return nil
}

// dingtalkHandler
func dingtalkHandler(w http.ResponseWriter, r *http.Request) {
	noticeInfo := &sonarScanResult{}
	err := parseWebhook(noticeInfo, r)
	if err != nil {
		log.Println("解析webhook调用参数异常." + err.Error())
	}
	err = requestScanResult(noticeInfo)
	if err != nil {
		log.Println("请求sonar异常." + err.Error())
	}
	// 成功失败标志
	var picUrl string
	if noticeInfo.alterStatus == "OK" {
		picUrl = "http://s1.ax1x.com/2020/10/29/BGMeTe.png"
	} else {
		picUrl = "http://s1.ax1x.com/2020/10/29/BGMZwD.png"
	}
	// 发送钉钉消息
	msgUrl := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", noticeInfo.accessToken)
	var messageUrl string
	if programCommand.multiBranch {
		messageUrl = fmt.Sprintf("%s", noticeInfo.branchUrl)
	} else {
		messageUrl = fmt.Sprintf("%s/dashboard?id=%s", noticeInfo.serverUrl, noticeInfo.projectKey)
	}

	link := make(map[string]string)
	link["title"] = fmt.Sprintf("%s[%s]代码扫描报告", noticeInfo.projectName, noticeInfo.branchName)
	branchStatus := fmt.Sprintf("Bugs: %s | 漏洞: %s | 异味: %s\r覆盖率: %s%%\r重复率: %s%%\n\n",
		noticeInfo.bugs, noticeInfo.vulnerabilities, noticeInfo.codeSmells, noticeInfo.coverage, noticeInfo.duplicatedLines)
	newCodeStatus := fmt.Sprintf("新增Bugs: %s | 新增漏洞: %s | 新增异味: %s\r覆盖率: %s%%\r重复率: %s%%",
		noticeInfo.new_bugs, noticeInfo.new_vulnerabilities, noticeInfo.new_codeSemlls, noticeInfo.new_coverage, noticeInfo.new_duplicatedLines)
	link["text"] = branchStatus + newCodeStatus
	link["messageUrl"] = messageUrl
	link["picUrl"] = picUrl

	param := make(map[string]interface{})
	param["msgtype"] = "link"
	param["link"] = link

	// send dingtalk message
	paramBytes, _ := json.Marshal(param)
	dingTalkRsp, _ := http.Post(msgUrl, "application/json", bytes.NewBuffer(paramBytes))
	dingTalkObj := make(map[string]interface{})
	json.NewDecoder(dingTalkRsp.Body).Decode(&dingTalkObj)
	if dingTalkObj["errcode"].(float64) != 0 {
		fmt.Fprint(w, "消息推送失败，请检查钉钉机器人配置")
		return
	}
	fmt.Fprint(w, "消息推送成功")
}

func main() {
	initCommand()
	http.HandleFunc("/dingtalk", dingtalkHandler)
	address := fmt.Sprintf("%s:%d", programCommand.host, programCommand.port)
	log.Printf("Server started on port(s): %s (http)\n", address)
	log.Printf("Support multiple-branch: %v \n", programCommand.multiBranch)

	log.Fatal(http.ListenAndServe(address, nil))
}
