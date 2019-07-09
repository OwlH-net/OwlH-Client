package main

import (
    "fmt"
    "os"
    "encoding/json"
    "io/ioutil"
    "github.com/google/gopacket/pcap"
    "strings"
    "net"
    "os/exec"
    "time"
    //"strconv"
)

func readConfig()(config map[string]interface{}, err error) {
    confFile, err := os.Open("conf.json")
    if err != nil {
        fmt.Println(err)
        return nil, err
    }
    defer confFile.Close()
    byteValue, _ := ioutil.ReadAll(confFile)
    //var config map[string]interface{}
    json.Unmarshal([]byte(byteValue), &config)
    return config, nil
}

func readInterfaces()(devices []pcap.Interface, err error){
    devices, err = pcap.FindAllDevs()
    if err != nil {
        return nil, err
    }
    return devices, err
}

func inNET(s []interface{}, nets []pcap.InterfaceAddress ) bool {
    for _, a := range s {
        _, ipv4Net, _ := net.ParseCIDR(a.(string))
        for eachIp := range nets {
            if ipv4Net.Contains(nets[eachIp].IP){
                return true
            }
        }
    }
    return false
}

func inIPs(s []interface{},ips []pcap.InterfaceAddress ) bool{
    for _, a := range s {
        for _, mynet := range ips {
            if mynet.IP.String() == a.(string){
                return true
            }
        }

    }
    return false
}

func createListenMap(config map[string]interface{}, interfaces []pcap.Interface)(listenMap []string, err error) {
    for _, localInt := range interfaces {
        includeInterfaces, _ := config["includeInt"].([]interface{})
        if contains(includeInterfaces,localInt.Name) == false {
            continue
        }
        excludeInterfaces, _ := config["excludeInt"].([]interface{})
        if contains(excludeInterfaces,localInt.Name) == true {
            continue
        }
        includeNets, _ := config["includeNet"].([]interface{})
        if inNET(includeNets, localInt.Addresses) == false {
            continue
        }
        excludeIPs, _ := config["excludeIP"].([]interface{})
        if inIPs(excludeIPs, localInt.Addresses) == true {
            continue
        }
        listenMap = append(listenMap, localInt.Name)
    }
    return listenMap, nil
}

func contains(s []interface{}, e string) bool {
    for _, a := range s {
        fmt.Printf("%s -> %s",a.(string),e)
        if strings.Contains(e, a.(string)) {
            fmt.Println(" -- TRUE")
            return true
        }
        fmt.Println(" -- FALSE")
    }
    return false
}

func isRuning (listenToInterface string)bool {
    tcpdump:=false
    socat:=false
    cmd := "ps -ef | grep tcpdump | grep -i "+listenToInterface + " | grep -v grep"
    isListening, err := exec.Command("bash", "-c", cmd).Output()
    if strings.Contains(string(isListening), listenToInterface){
        tcpdump =true
    }
    cmd = "ps -ef | grep socat | grep -i "+listenToInterface + " | grep -v grep"
    isListening, _ = exec.Command("bash", "-c", cmd).Output()
    if strings.Contains(string(isListening), listenToInterface){
        socat =true
    }
    fmt.Println(tcpdump, socat)
    if tcpdump == true && socat == true {
        return true
    }
    fmt.Println("reset")
    if tcpdump == false {
        cmd = "/bin/kill -9 $(ps -ef | grep socat | grep -i "+listenToInterface +" |  awk '{print $2}')"
        fmt.Println(cmd)
        kills := exec.Command("bash", "-c", cmd)
        err = kills.Start()
        if err != nil {
           fmt.Printf("Trying to kill socat -> %s", err.Error())
        }
    }
    if socat == false {
        cmd = "/bin/kill -9 $(ps -ef | grep tcpdump | grep -i "+listenToInterface +" |  awk '{print $2}')"
        fmt.Println(cmd)
        killt := exec.Command("bash", "-c", cmd)
        err = killt.Start()
        if err != nil {
           fmt.Printf("Trying to kill tcpdump -> %s", err.Error())
        }
    }
    return false
}

func forwardTraffic(config map[string]interface{}, listenMap []string) error {
    collectorIP := config["collectorIP"].(string)
    collectorPort := config["collectorPort"].(string)
    cert := config["cert"].(string)
    bpf := config["bpf"].(string)
    for listenInt := range listenMap {
        if isRuning(listenMap[listenInt]) == false {
            fmt.Printf("stap on %s interface isn't runing\n",listenMap[listenInt])
            fmt.Println("will run with params - ",listenMap[listenInt], " ", collectorIP," ", collectorPort, " ", cert," ", bpf)
            txtCMD := "/usr/sbin/tcpdump -nn -i "+listenMap[listenInt]+" -s 0 -w - "+config["bpf"].(string)+" | /usr/bin/socat -lf"+listenMap[listenInt]+" - OPENSSL:"+config["collectorIP"].(string)+":"+config["collectorPort"].(string)+",cert="+config["cert"].(string)+",verify=0,forever,retry=10,interval=5 2>&1 &"
            fmt.Println(txtCMD)
            cmd := exec.Command("bash","-c",txtCMD)
            err := cmd.Start()
            if err != nil {
                fmt.Printf("Trying to run command -> %s", err)
            }
        }
    }
    return nil
}


func mainLoop(){
    config, err := readConfig()
    if err != nil {
        fmt.Printf("error reading config > %s\n", err.Error())
        os.Exit(1)
    }
    fmt.Println(config)
    interfaces, err := readInterfaces()
    if err != nil {
        fmt.Printf("error reading Interfaces > %s\n", err.Error())
    }
    fmt.Println(interfaces)
    listenMap, err := createListenMap(config, interfaces)
    if err != nil {
        fmt.Printf("error creating > %s\n", err.Error())
    }
    fmt.Println(listenMap)
    err = forwardTraffic(config, listenMap)
    if err != nil {
        fmt.Printf("error starting to listen > %s\n", err.Error())
    }
    fmt.Println(config["waitTime"])
    timetowait := time.Duration(int(config["waitTime"].(float64)))
    time.Sleep(timetowait * time.Minute)
}


func main(){
    fmt.Println("welcome")
    for {
        mainLoop()

    }
}

