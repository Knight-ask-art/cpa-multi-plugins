package main

import (
	"encoding/json"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// handleHiddenModels answers POST <base>/hidden-models (v0.8.77).
//
//	body: {"remove": ["deepseek-flash"]}
//	resp: {hidden_models: [...remaining], removed: [...], config_yaml: "...",
//	       needs_config_edit: true}
//
// The live list changes immediately so the catalog updates without a restart;
// config.yaml is NOT touched (the host owns it) and the response carries the
// replacement block the operator pastes in. needs_config_edit is what tells the
// panel to show that block — without it the entry would silently return on the
// next CPA restart.
func handleHiddenModels(req pluginapi.ManagementRequest) map[string]any {
	var body struct {
		Remove []string `json:"remove"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		return map[string]any{"error": "invalid body: " + err.Error()}
	}
	if len(body.Remove) == 0 {
		return map[string]any{"error": "remove is required"}
	}
	remaining, removed := removeHiddenModels(body.Remove)
	if len(removed) == 0 {
		return map[string]any{
			"hidden_models": remaining,
			"removed":       []string{},
			"message":       "这些条目已不在 hidden_models 里",
		}
	}
	return map[string]any{
		"hidden_models":     remaining,
		"removed":           removed,
		"config_yaml":       hiddenModelsYAMLBlock(remaining),
		"needs_config_edit": true,
		"note":              strings.TrimSpace("已在内存中生效；把 config_yaml 覆盖到 config.yaml 的 qoder 配置节，否则重启后这些条目会重新隐藏"),
	}
}
