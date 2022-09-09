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
	s.projectUrl = getMapValue(sonarRsp["project"], "url")
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

func dingTalkNotice(s *sonarScanResult) error {
	// 构建钉钉消息
	var color string
	if s.alterStatus == "OK" {
		color = "#008000"
	} else {
		color = "#FF0000"
	}
	scanResultText := fmt.Sprintf("**扫描结果**: <font color='%s'>%s</font> \n - - - \n\n", color, s.alterStatus)
	projectInfo := fmt.Sprintf("**项目名称**: [%s](%s)(项目首页) \n\n**项目分支**: [%s](%s)(分支信息) \n- - -\n\n", s.projectName, s.projectUrl, s.branchName, s.branchUrl)
	newCodeStatus := fmt.Sprintf("**新增Bugs**: %s  |  **新增漏洞**: %s | **新增异味**: %s\n **覆盖率**: %s%% | **重复率**: %s%% \n - - - \n\n",
		s.new_bugs, s.new_vulnerabilities, s.new_codeSemlls, s.new_coverage, s.new_duplicatedLines)
	branchStatus := fmt.Sprintf("**Bugs**: %s | **漏洞**: %s | **异味**: %s\n**覆盖率**: %s%% | **重复率**: %s%% \n - - - \n\n",
		s.bugs, s.vulnerabilities, s.codeSmells, s.coverage, s.duplicatedLines)
	// 创建钉钉通知请求
	markdown := make(map[string]string)
	markdown["text"] = scanResultText + projectInfo + newCodeStatus + branchStatus
	markdown["title"] = "代码扫描报告"
	param := make(map[string]interface{})
	param["msgtype"] = "markdown"
	param["markdown"] = markdown

	// 发送钉钉消息
	paramBytes, _ := json.Marshal(param)
	msgUrl := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s", s.accessToken)
	dingTalkRsp, _ := http.Post(msgUrl, "application/json", bytes.NewBuffer(paramBytes))
	dingTalkObj := make(map[string]interface{})
	json.NewDecoder(dingTalkRsp.Body).Decode(&dingTalkObj)
	if dingTalkObj["errcode"].(float64) != 0 {
		return errors.New("请检查钉钉机器人配置")
	}
	return nil
}

// dingtalkHandler
func dingtalkHandler(w http.ResponseWriter, r *http.Request) {
	noticeInfo := &sonarScanResult{}
	// 解析webhook
	err := parseWebhook(noticeInfo, r)
	if err != nil {
		log.Println("解析webhook调用参数异常." + err.Error())
	}
	// 请求并解析webapi结果
	err = requestScanResult(noticeInfo)
	if err != nil {
		log.Println("请求sonar异常." + err.Error())
	}
	// 钉钉通知
	err = dingTalkNotice(noticeInfo)
	if err != nil {
		_, _ = fmt.Fprint(w, "消息推送失败: "+err.Error())
	} else {
		_, _ = fmt.Fprint(w, "消息推送成功")
	}

}

func main() {
	initCommand()
	http.HandleFunc("/dingtalk", dingtalkHandler)
	address := fmt.Sprintf("%s:%d", programCommand.host, programCommand.port)
	log.Printf("Server started on port(s): %s (http)\n", address)
	log.Printf("Support multiple-branch: %v \n", programCommand.multiBranch)

	log.Fatal(http.ListenAndServe(address, nil))
}
