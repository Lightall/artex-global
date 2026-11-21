package agent

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/db"
)

// taskScopeContext is a program-owned system block, independent of editable
// constraints and compactable graph summaries. It describes structured gates,
// without claiming to sandbox arbitrary execution tools.
func taskScopeContext(as *db.AssetStore, taskID int64) (string, error) {
	if as == nil || taskID <= 0 {
		return "", nil
	}
	gate, err := as.LoadTaskAssetGate(taskID)
	if err != nil {
		return "", err
	}
	if !gate.DomainScopeEnabled {
		return "", nil
	}
	type ruleView struct {
		Enabled bool   `json:"enabled"`
		Kind    string `json:"kind"`
		Pattern string `json:"pattern"`
	}
	rules := func(in []db.AssetInterceptRule) []ruleView {
		out := make([]ruleView, 0, len(in))
		for _, r := range in {
			out = append(out, ruleView{r.Enabled, r.Kind, r.Pattern})
		}
		return out
	}
	data, err := json.Marshal(map[string]any{"input_domains": gate.Domains, "allow_rules": rules(gate.AllowRules), "block_rules": rules(gate.BlockRules)})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("\n\n【任务域名范围（程序读取的持久化配置）】\n%s\n所有 input_domains 均属于本任务输入，规划时逐一考虑。Worker 仍只执行自己领到的意图。当前允许与拦截规则决定结构化资产操作能否通过；父域、绑定域名及关联任务的资料不自动扩大授权。此范围块独立于可编辑提示词与全局态势摘要。", data), nil
}
