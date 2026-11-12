package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/verification"
	actool "github.com/Autumn-27/norma/tool"
)

func (s *Server) putHTTPVerification(w http.ResponseWriter, r *http.Request) {
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "bad task id")
		return
	}
	var cfg verification.Config
	if !decodeConversationRequest(w, r, &cfg) {
		return
	}
	s.m.taskStateMu.Lock()
	defer s.m.taskStateMu.Unlock()
	if err := s.m.pg.SetHTTPVerificationConfig(r.Context(), id, cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"configured": true, "cases": len(cfg.Cases)})
}

func (s *Server) httpVerificationTools() []actool.CoreTool {
	run := func(kind string) func(context.Context, json.RawMessage) (actool.Result, error) {
		return func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var args struct {
				CaseID string `json:"case_id"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			ri := agent.RunInfoFrom(ctx)
			if ri.TaskID <= 0 || ri.IntentID <= 0 {
				return actool.Errorf("HTTP verification requires a running task worker"), nil
			}
			attempt, item, auth, err := s.m.pg.StartHTTPAttempt(ctx, ri.TaskID, ri.IntentID, args.CaseID, kind)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			runner := verification.Runner{Reserve: func(c context.Context) error { return s.m.pg.ReserveVerificationRequest(c, ri.TaskID, item) }}
			var obs []verification.Observation
			cause := ""
			if kind == "refresh" {
				var e error
				obs, _, e = runner.Refresh(ctx, item)
				if e != nil {
					cause = e.Error()
				}
			} else {
				obs = runner.Run(ctx, item, auth)
			}
			if ctx.Err() != nil {
				s.m.pg.AbortHTTPAttempt(attempt.ID, obs, "interrupted")
				return actool.Errorf(ctx.Err().Error()), nil
			}
			out, err := s.m.pg.FinishHTTPAttempt(ctx, attempt.ID, obs, cause)
			if err != nil {
				s.m.pg.AbortHTTPAttempt(attempt.ID, obs, "receipt_persistence_failed")
				return actool.Errorf(err.Error()), nil
			}
			// Persist the prerequisite gap as an ordinary fact so the existing planner
			// wake-up and intent graph carry it; observations stay in the receipt store.
			task, ok := s.m.Task(strconv.FormatInt(ri.TaskID, 10))
			if ok {
				payload := map[string]any{"summary": "HTTP experiment " + out.CaseID + ": " + out.Verdict + " (" + out.Reason + ")", "attempt_id": out.ID, "case_id": out.CaseID, "verdict": out.Verdict, "reason": out.Reason, "confidence": "observed"}
				if fid, e := task.Store.AddNode("fact", payload, 5, "confirmed", "verification", item.AssetIDs); e == nil {
					_ = task.Store.Link(ri.IntentID, "yields", fid)
				}
				task.Notify()
			}
			return jsonResult(out)
		}
	}
	return []actool.CoreTool{
		wrTool("run_http_case", "执行 operator 配置的本地 HTTP 双账号读取越权用例；核对身份、正常对照、测试请求和隔离客户端重复。返回真实 attempt_id 与 reproduced/not_reproduced/inconclusive，不能自行指定判据。", objSchema(map[string]any{"case_id": strParam("graph_overview.verification.cases 中的 case_id")}, "case_id"), run("verify")),
		wrTool("refresh_http_case_auth", "按 operator 配置刷新本地测试用例的登录态并核对真实身份。只补齐已观察到的前置缺口；每 case 版本最多一次。不会把未复现记为修复。", objSchema(map[string]any{"case_id": strParam("已配置的 case_id")}, "case_id"), run("refresh")),
		roTool("get_http_case_attempt", "读取本任务实验的真实验证观察。登录响应不展示，防止把凭据带入模型。", objSchema(map[string]any{"attempt_id": map[string]any{"type": "integer"}}, "attempt_id"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var args struct {
				ID int64 `json:"attempt_id"`
			}
			if err := json.Unmarshal(in, &args); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			a, err := s.m.pg.GetTestAttempt(ctx, args.ID)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if a.TaskID != agent.RunInfoFrom(ctx).TaskID {
				return actool.Errorf("attempt does not belong to this task"), nil
			}
			var observations []map[string]any
			for _, o := range a.Observations {
				b := "[login response withheld]"
				if a.Kind == "verify" {
					b = string(o.Body)
				}
				observations = append(observations, map[string]any{"phase": o.Phase, "url": o.URL, "status": o.Status, "body": b, "sha256": o.BodyHash, "error": o.Error})
			}
			return jsonResult(map[string]any{"attempt": a, "observations": observations})
		}),
	}
}

func (s *Server) seedHTTPVerificationTools() error {
	for _, tool := range s.httpVerificationTools() {
		schema, _ := json.Marshal(tool.InputSchema())
		bindings, _ := json.Marshal([]string{"worker"})
		if err := s.m.pg.SeedTool(tool.Name(), tool.Description(), schema, bindings); err != nil {
			return err
		}
	}
	// Additive schema migration preserves edited descriptions and agent bindings.
	tool, err := s.m.pg.GetTool("report_finding")
	if err != nil {
		return err
	}
	if tool == nil {
		return errors.New("report_finding not seeded")
	}
	for key, schema := range map[string]any{"attempt_id": map[string]any{"type": "integer"}, "verification_case_id": map[string]any{"type": "string"}} {
		raw, _ := json.Marshal(schema)
		if _, err = s.m.pg.Exec(`UPDATE tools SET schema=jsonb_set(schema,ARRAY['properties',$1::text],$2::jsonb,true) WHERE key='report_finding' AND NOT(COALESCE(schema->'properties','{}'::jsonb) ? $1)`, key, raw); err != nil {
			return err
		}
	}
	return nil
}
