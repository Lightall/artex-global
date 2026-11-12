package agent

import (
	"context"
	"encoding/json"
	"fmt"

	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) listSecurityExperiments() actool.CoreTool {
	return t.readExpTool("list_security_experiments", "列出本任务由操作者配置的身份/对象隔离实验及最新结果。not_reproduced 只适用于指定身份、对象和当次业务状态；precondition_failed/inconclusive/running 不能封锁漏洞方向。未执行或前置条件不足时，派意图让 worker 执行或补齐条件。配置和安全预期只能由操作者通过任务 API 登记，不能用模型猜测替代。", obj(map[string]any{}), func(context.Context, json.RawMessage) (actool.Result, error) {
		items, err := t.ts.SecurityExperiments()
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return jsonResult(map[string]any{"experiments": items})
	})
}

func (t *ToolSet) runSecurityExperiment() actool.CoreTool {
	return t.writeExpTool("run_security_experiment", "执行一个操作者已配置的只读身份/对象隔离实验。只接受 case_id 与当前 intent_id，不能改目标、凭据、业务规则或预期。程序核验双方身份、正常对照、资源归属，并重复测试，保存真实响应及哈希；不调用模型。结果为 violation_observed / not_reproduced / precondition_failed / inconclusive。有效阳性先用 report_finding(experiment_evidence_id=返回的 evidence_id) 登记漏洞，之后才能 prove_goal，报告 Agent 通过漏洞详情读取完整证据。其他结果保持范围和未知，不能宣称安全或目标达成。", obj(map[string]any{"case_id": idp("list_security_experiments 返回的本任务 case_id"), "intent_id": idp("当前意图 ID")}, "case_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			CaseID   json.RawMessage `json:"case_id"`
			IntentID json.RawMessage `json:"intent_id"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if pid(a.CaseID) <= 0 {
			return actool.Errorf("case_id 必须是有效的本任务实验编号"), nil
		}
		intent := pid(a.IntentID)
		if intent == 0 {
			intent = t.ownerNode
		}
		// Planner/main roots are not intents. Only workers supply ownerNode here.
		if intent == t.ownerNode && intent > 0 {
			n, err := t.ts.GetNode(intent)
			if err != nil || n == nil || n.Kind != "intent" {
				intent = 0
			}
		}
		run, err := t.ts.RunSecurityExperiment(ctx, t.taskID, pid(a.CaseID), intent)
		if err != nil {
			if run != nil {
				return actool.Errorf(fmt.Sprintf("实验 #%d 结算失败，结果尚未确认为已保存：%v", run.ID, err)), nil
			}
			return actool.Errorf(err.Error()), nil
		}
		t.writes.Facts++
		if t.notify != nil {
			t.notify()
		}
		next := "preserve_unknown_or_scoped_negative; do not report a confirmed finding"
		if run.Result.Verdict == "violation_observed" {
			next = "report_finding(experiment_evidence_id=evidence_id), then prove_goal"
		}
		return jsonResult(map[string]any{"evidence_id": run.ID, "case_id": run.CaseID, "verdict": run.Result.Verdict, "reason": run.Result.Reason, "observations": len(run.Result.Observations), "spec_fingerprint": run.Result.SpecFingerprint, "next_action": next})
	})
}

func (t *ToolSet) getSecurityExperiment() actool.CoreTool {
	return t.readExpTool("get_security_experiment", "读取本任务某次身份/对象隔离实验的完整持久证据：身份、对象及配置指纹、真实响应体、哈希、截断/脱敏标记。凭据值不会返回。运行中或结算失败的记录保持未知，不能当完成证据。", obj(map[string]any{"evidence_id": idp("run_security_experiment 返回的 evidence_id")}, "evidence_id"), func(_ context.Context, in json.RawMessage) (actool.Result, error) {
		var a struct {
			ID json.RawMessage `json:"evidence_id"`
		}
		if err := json.Unmarshal(in, &a); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		run, err := t.ts.SecurityExperimentEvidence(pid(a.ID))
		if err != nil {
			return actool.Errorf(err.Error()), nil
		}
		return jsonResult(run)
	})
}
