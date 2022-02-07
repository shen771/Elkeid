package http_handler

import (
	"fmt"
	"github.com/bytedance/Elkeid/server/agent_center/common/ylog"
	"github.com/bytedance/Elkeid/server/agent_center/grpctrans/grpc_handler"
	"github.com/gin-gonic/gin"
)

const (
	ConnResetRandom = "random"
	ConnResetStrict = "strict"
)

type ResetRequest struct {
	IDList []string `json:"id_list"`
	Type   string   `json:"type" binding:"required" `
	Count  int      `json:"count"`
}

type ConnStatRsp struct {
	AgentInfo   map[string]interface{}   `json:"agent_info"`
	PluginsInfo []map[string]interface{} `json:"plugins_info"`
}

func ConnStat(c *gin.Context) {
	res := grpc_handler.GlobalGRPCPool.GetList()
	ylog.Debugf("ConnStat", ">>>>API ConnStat connMap len: %d", len(res))
	resList := make([]ConnStatRsp, 0, len(res))
	for _, v := range res {
		tmp := ConnStatRsp{
			AgentInfo:   v.GetAgentDetail(),
			PluginsInfo: v.GetPluginsList(),
		}
		resList = append(resList, tmp)
	}
	CreateResponse(c, SuccessCode, resList)
	return
}

func ConnList(c *gin.Context) {
	res := grpc_handler.GlobalGRPCPool.GetList()
	ylog.Debugf("ConnStat", ">>>>API ConnStat connMap len: %d", len(res))
	resList := make([]string, 0, len(res))
	for _, v := range res {
		resList = append(resList, v.AgentID)
	}
	CreateResponse(c, SuccessCode, resList)
	return
}

func ConnCount(c *gin.Context) {
	count := grpc_handler.GlobalGRPCPool.GetCount()
	ylog.Debugf("ConnCount", ">>>>API ConnCount %d", count)
	CreateResponse(c, SuccessCode, count)
	return
}

func ConnReset(c *gin.Context) {
	var param ResetRequest
	err := c.BindJSON(&param)
	if err != nil {
		ylog.Errorf("ConnReset", ">>>>ConnReset Parse para error : %s", err.Error())
		CreateResponse(c, ParamInvalidErrorCode, err.Error())
		return
	}

	res := gin.H{}
	detail := gin.H{}
	switch param.Type {
	case ConnResetRandom:
		conn := grpc_handler.GlobalGRPCPool.GetList()
		id := 0
		for id = 0; id < param.Count && id < len(conn); id++ {
			agentID := conn[id].AgentID
			err := grpc_handler.GlobalGRPCPool.Close(agentID)
			if err != nil {
				detail[agentID] = err.Error()
			} else {
				detail[agentID] = "ok"
			}
		}
		res["count"] = id
		res["detail"] = detail
	case ConnResetStrict:
		for _, v := range param.IDList {
			err := grpc_handler.GlobalGRPCPool.Close(v)
			if err != nil {
				detail[v] = err.Error()
			} else {
				detail[v] = "ok"
			}
		}
		res["count"] = len(param.IDList)
		res["detail"] = detail
	default:
		CreateResponse(c, ParamInvalidErrorCode, fmt.Sprintf("type only support %s|%s", ConnResetStrict, ConnResetRandom))
		return
	}

	CreateResponse(c, SuccessCode, res)
	return
}
