package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

// ================= Common =================

type AnthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ================= Anthropic New (/v1/messages) =================

type AnthropicMessagesReq struct {
	Model    string          `json:"model,omitempty"`
	System   json.RawMessage `json:"system,omitempty"`
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	MaxTokens     any  `json:"max_tokens"` // Use any to handle varied types
	Temperature   any  `json:"temperature,omitempty"`
	TopP          any  `json:"top_p,omitempty"`
	TopK          any  `json:"top_k,omitempty"`
	Stream        bool `json:"stream,omitempty"`
	StopSequences any  `json:"stop_sequences,omitempty"`
	Tools         any  `json:"tools,omitempty"`
}

// ================= Anthropic Old (/v1/complete) =================

type AnthropicCompleteReq struct {
	Prompt      string  `json:"prompt"`
	MaxTokens   int     `json:"max_tokens_to_sample"`
	Temperature float64 `json:"temperature,omitempty"`
	Stream      bool    `json:"stream,omitempty"`
}

// ================= OpenAI-compatible =================

type OAChatReq struct {
	Model       string      `json:"model"`
	Messages    []OAMessage `json:"messages"`
	MaxTokens   int         `json:"max_tokens,omitempty"`
	Temperature float64     `json:"temperature,omitempty"`
	Stream      bool        `json:"stream,omitempty"`
	Tools       any         `json:"tools,omitempty"`
}

type OAMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// stream chunk
type OAStreamChunk struct {
	Choices []struct {
		Delta struct {
			Content          string          `json:"content,omitempty"`
			ReasoningContent string          `json:"reasoning_content,omitempty"`
			Reasoning        string          `json:"reasoning,omitempty"` // 兼容某些厂商的字段名
			ToolCalls        json.RawMessage `json:"tool_calls,omitempty"`
		} `json:"delta"`
	} `json:"choices"`
}

// Anthropic Models API
type AnthropicModel struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
}

type AnthropicModelsResp struct {
	Data    []AnthropicModel `json:"data"`
	HasMore bool             `json:"has_more"`
}

// OpenAI Models
type OAModel struct {
	ID string `json:"id"`
}

type OAModelsResp struct {
	Data []OAModel `json:"data"`
}

// OpenAI Non-stream Response
type OAChatResp struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content          string `json:"content"`
			ReasoningContent string `json:"reasoning_content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func main() {
	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = ":0"
	}

	base := os.Getenv("OPENAI_BASE_URL")
	model := os.Getenv("OPENAI_MODEL")
	if base == "" || model == "" {
		log.Fatal("OPENAI_BASE_URL / OPENAI_MODEL required")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/messages", messagesHandler(base, model))
	mux.HandleFunc("/v1/complete", completeHandler(base, model))
	mux.HandleFunc("/v1/models", modelsHandler(base))

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("listening on", ln.Addr())

	srv := &http.Server{Handler: mux}
	log.Fatal(srv.Serve(ln))
}

// ================= Handlers =================

func messagesHandler(base, model string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			auth = r.Header.Get("x-api-key")
		}
		if auth == "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			auth = "Bearer " + auth
		}

		var req AnthropicMessagesReq
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "error reading request", 400)
			return
		}
		if err := json.Unmarshal(b, &req); err != nil {
			log.Printf("JSON Unmarshal Error: %v | Body: %s", err, string(b))
			http.Error(w, "bad request: "+err.Error(), 400)
			return
		}

		msgs := make([]OAMessage, 0)
		// 处理 System 字段（可能是字符串或数组）
		if len(req.System) > 0 {
			var systemStr string
			var s string
			if err := json.Unmarshal(req.System, &s); err == nil {
				systemStr = s
			} else {
				var parts []AnthropicContent
				if err := json.Unmarshal(req.System, &parts); err == nil {
					var sb strings.Builder
					for _, p := range parts {
						if p.Type == "text" {
							sb.WriteString(p.Text)
						}
					}
					systemStr = sb.String()
				}
			}
			if systemStr != "" {
				msgs = append(msgs, OAMessage{Role: "system", Content: systemStr})
			}
		}

		for _, m := range req.Messages {
			var contentStr string
			// 尝试解析 content 为字符串
			var s string
			if err := json.Unmarshal(m.Content, &s); err == nil {
				contentStr = s
			} else {
				// 尝试解析 content 为对象数组
				var parts []AnthropicContent
				if err := json.Unmarshal(m.Content, &parts); err == nil {
					var sb strings.Builder
					for _, p := range parts {
						if p.Type == "text" {
							sb.WriteString(p.Text)
						}
					}
					contentStr = sb.String()
				}
			}
			msgs = append(msgs, OAMessage{Role: m.Role, Content: contentStr})
		}

		// 优先使用请求体中的模型名称
		targetModel := model
		if req.Model != "" {
			targetModel = req.Model
		}

		// 将 any 类型的参数转换为合理的数值
		var maxTokens int
		switch v := req.MaxTokens.(type) {
		case float64:
			maxTokens = int(v)
		case int:
			maxTokens = v
		}

		var temp float64
		if vt, ok := req.Temperature.(float64); ok {
			temp = vt
		}

		oa := OAChatReq{Model: targetModel, Messages: msgs, MaxTokens: maxTokens, Temperature: temp, Stream: req.Stream, Tools: req.Tools}
		forwardOA(w, r, base, auth, oa, req.Stream)
	}
}

func completeHandler(base, model string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			auth = r.Header.Get("x-api-key")
		}
		if auth == "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			auth = "Bearer " + auth
		}

		var req AnthropicCompleteReq
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "error reading request", 400)
			return
		}
		if err := json.Unmarshal(b, &req); err != nil {
			log.Printf("JSON Unmarshal Error (Complete): %v | Body: %s", err, string(b))
			http.Error(w, "bad request: "+err.Error(), 400)
			return
		}

		oa := OAChatReq{Model: model, Messages: []OAMessage{{Role: "user", Content: req.Prompt}}, MaxTokens: req.MaxTokens, Temperature: req.Temperature, Stream: req.Stream}
		forwardOA(w, r, base, auth, oa, req.Stream)
	}
}

func modelsHandler(base string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			auth = r.Header.Get("x-api-key")
		}

		req, _ := http.NewRequestWithContext(r.Context(), "GET", base+"/v1/models", nil)
		if auth != "" {
			if !strings.HasPrefix(auth, "Bearer ") {
				auth = "Bearer " + auth
			}
			req.Header.Set("Authorization", auth)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		defer resp.Body.Close()

		var oaResp OAModelsResp
		if err := json.NewDecoder(resp.Body).Decode(&oaResp); err != nil {
			http.Error(w, "failed to decode models", 500)
			return
		}

		anthResp := AnthropicModelsResp{
			Data:    make([]AnthropicModel, 0),
			HasMore: false,
		}

		for _, m := range oaResp.Data {
			anthResp.Data = append(anthResp.Data, AnthropicModel{
				Type:        "model",
				ID:          m.ID,
				DisplayName: m.ID,
				CreatedAt:   "2024-01-01T00:00:00Z", // Mock time
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(anthResp)
	}
}

// ================= Core Forward + Streaming FSM =================

func forwardOA(w http.ResponseWriter, r *http.Request, base, auth string, oa OAChatReq, stream bool) {
	// 修正 URL 拼接逻辑
	apiURL := strings.TrimSuffix(base, "/")
	if !strings.HasSuffix(apiURL, "/v1") {
		apiURL += "/v1"
	}
	apiURL += "/chat/completions"

	buf, err := json.Marshal(oa)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	or, err := http.NewRequestWithContext(r.Context(), "POST", apiURL, bytes.NewReader(buf))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	or.Header.Set("Authorization", auth)
	or.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(or)
	if err != nil {
		log.Printf("Upstream Request Error: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 如果上游返回错误状态
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(resp.Body)
		log.Printf("Upstream returned error (%d): %s", resp.StatusCode, string(rb))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(rb)
		return
	}

	if !stream {
		w.Header().Set("Content-Type", "application/json")
		var oaResp OAChatResp
		if err := json.NewDecoder(resp.Body).Decode(&oaResp); err != nil {
			http.Error(w, "failed to decode upstream response", 502)
			return
		}

		if len(oaResp.Choices) == 0 {
			http.Error(w, "empty upstream response", 502)
			return
		}

		// 组合内容
		// 解析 upstream 的 content，提取 <think> 标签内容
		rawContent := oaResp.Choices[0].Message.Content
		reasoningContent := oaResp.Choices[0].Message.ReasoningContent

		blocks := make([]map[string]any, 0)

		// 1. 如果有显式的 reasoning_content，先添加
		if reasoningContent != "" {
			blocks = append(blocks, map[string]any{
				"type":     "thinking",
				"thinking": reasoningContent,
			})
		}

		// 2. 解析正文中的 <think> 标签 (简单的 regex 或 string split)
		// 注意：这里假设 <think> 总是成对出现且不嵌套，或者只是一种简单的分割
		// 常见的模式是： <think> ... </think> ...
		// 或者 ... <think> ... </think>

		// 简单的解析器：
		inThinking := false
		lastPos := 0

		// 查找所有 tag
		for {
			var tagIdx int
			var tagLen int
			var isStart bool

			startIdx := strings.Index(rawContent[lastPos:], "<think>")
			endIdx := strings.Index(rawContent[lastPos:], "</think>")

			if startIdx == -1 && endIdx == -1 {
				break
			}

			// 决定下一个是 start 还是 end
			if startIdx != -1 && (endIdx == -1 || startIdx < endIdx) {
				tagIdx = lastPos + startIdx
				tagLen = 7 // len("<think>")
				isStart = true
			} else {
				tagIdx = lastPos + endIdx
				tagLen = 8 // len("</think>")
				isStart = false
			}

			// 处理 tag 之前的内容
			preText := rawContent[lastPos:tagIdx]
			if preText != "" {
				if inThinking {
					blocks = append(blocks, map[string]any{"type": "thinking", "thinking": preText})
				} else {
					blocks = append(blocks, map[string]any{"type": "text", "text": preText})
				}
			}

			// 更新状态
			if isStart {
				inThinking = true // 进入 thinking 模式
			} else {
				inThinking = false // 退出 thinking 模式
			}

			lastPos = tagIdx + tagLen
		}

		// 处理剩余内容
		remaining := rawContent[lastPos:]
		if remaining != "" {
			if inThinking {
				// 如果结束了还在 thinking 模式（例如没有闭合标签），就当作 thinking
				blocks = append(blocks, map[string]any{"type": "thinking", "thinking": remaining})
			} else {
				blocks = append(blocks, map[string]any{"type": "text", "text": remaining})
			}
		}

		// 如果 blocks 为空 (即 content 为空且无 reasoning)，由于 Anthropic 要求 content 不为空，加一个空 text
		if len(blocks) == 0 {
			blocks = append(blocks, map[string]any{"type": "text", "text": ""})
		}

		anthResp := map[string]any{
			"id":            "msg_" + oaResp.ID,
			"type":          "message",
			"role":          "assistant",
			"model":         oaResp.Model,
			"content":       blocks,
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
			"usage": map[string]any{
				"input_tokens":  oaResp.Usage.PromptTokens,
				"output_tokens": oaResp.Usage.CompletionTokens,
			},
		}
		json.NewEncoder(w).Encode(anthResp)
		return
	}

	// HTTP/2 + streaming
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher := w.(http.Flusher)
	// 使用 Reader 代替 Scanner 以支持超长单行数据
	reader := bufio.NewReader(resp.Body)

	startedMessage := false
	currentBlockType := "" // "thinking" or "text" or ""
	currentBlockIdx := -1

	// Buffer for parsing <think> tags in content
	contentBuffer := ""

	// Helper to emit delta for current block type
	emitDelta := func(text string) {
		if text == "" {
			return
		}
		// 确保块已启动
		if currentBlockType == "" {
			currentBlockIdx++
			currentBlockType = "text"
			w.Write([]byte(fmt.Sprintf("event: content_block_start\ndata: {\"type\": \"content_block_start\", \"index\": %d, \"content_block\": {\"type\": \"text\", \"text\": \"\"}}\n\n", currentBlockIdx)))
		}

		switch currentBlockType {
		case "thinking":
			// Wrap thinking delta in content_block_delta
			evt, _ := json.Marshal(map[string]any{
				"type":  "content_block_delta",
				"index": currentBlockIdx,
				"delta": map[string]string{
					"type":     "thinking_delta",
					"thinking": text,
				},
			})
			// Add explicit event type for better compatibility
			w.Write([]byte("event: content_block_delta\n"))
			w.Write([]byte("data: "))
			w.Write(evt)
			w.Write([]byte("\n\n"))
		case "text":
			evt, _ := json.Marshal(map[string]any{
				"type":  "content_block_delta",
				"index": currentBlockIdx,
				"delta": map[string]string{
					"type": "text_delta",
					"text": text,
				},
			})
			w.Write([]byte("event: content_block_delta\n"))
			w.Write([]byte("data: "))
			w.Write(evt)
			w.Write([]byte("\n\n"))
		}
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")

		if data == "[DONE]" {
			// 结束当前块
			if currentBlockIdx >= 0 {
				w.Write([]byte(fmt.Sprintf("event: content_block_stop\ndata: {\"type\": \"content_block_stop\", \"index\": %d}\n\n", currentBlockIdx)))
			}
			w.Write([]byte("event: message_delta\ndata: {\"type\": \"message_delta\", \"delta\": {\"stop_reason\": \"end_turn\", \"stop_sequence\": null}, \"usage\": {\"output_tokens\": 0}}\n\n"))
			w.Write([]byte("event: message_stop\ndata: {\"type\": \"message_stop\"}\n\n"))
			flusher.Flush()
			return
		}

		var chunk OAStreamChunk
		if json.Unmarshal([]byte(data), &chunk) != nil || len(chunk.Choices) == 0 {
			continue
		}

		if !startedMessage {
			w.Write([]byte("event: message_start\ndata: {\"type\": \"message_start\", \"message\": {\"id\": \"msg_proxy\", \"type\": \"message\", \"role\": \"assistant\", \"content\": [], \"model\": \"" + oa.Model + "\", \"stop_reason\": null, \"stop_sequence\": null, \"usage\": {\"input_tokens\": 0, \"output_tokens\": 0}}}\n\n"))
			startedMessage = true
		}

		d := chunk.Choices[0].Delta
		reasoning := d.ReasoningContent
		if reasoning == "" {
			reasoning = d.Reasoning
		}

		// 处理思维内容 (thinking)
		if reasoning != "" {
			if currentBlockType != "thinking" {
				// 如果之前在 text 块，先结束它（虽然通常 reasoning 在前）
				if currentBlockType == "text" {
					w.Write([]byte(fmt.Sprintf("event: content_block_stop\ndata: {\"type\": \"content_block_stop\", \"index\": %d}\n\n", currentBlockIdx)))
				}
				currentBlockIdx++
				currentBlockType = "thinking"
				w.Write([]byte(fmt.Sprintf("event: content_block_start\ndata: {\"type\": \"content_block_start\", \"index\": %d, \"content_block\": {\"type\": \"thinking\", \"thinking\": \"\"}}\n\n", currentBlockIdx)))
			}
			evt, _ := json.Marshal(map[string]any{
				"type":     "thinking_delta",
				"index":    currentBlockIdx,
				"thinking": reasoning,
			})
			w.Write([]byte("data: "))
			w.Write(evt)
			w.Write([]byte("\n\n"))
		}

		// 处理正文内容 (text)，带 <think> 标签解析
		if d.Content != "" {
			contentBuffer += d.Content
		}

		// 循环处理 buffer 中的标签
		for {
			// 查找可能的标签
			startTagIdx := strings.Index(contentBuffer, "<think>")
			endTagIdx := strings.Index(contentBuffer, "</think>")

			// 如果没有找到完整标签
			if startTagIdx == -1 && endTagIdx == -1 {
				// 检查是否有 partial tag 在末尾 (防止切断)
				// 最长 potential tag 前缀是 7 ("</think" 除去最后一个 >) -> check last 7 chars
				cutoff := len(contentBuffer)
				possibleTag := false

				// 简单的 heuristic: 检查末尾是否含有 '<' 且后续字符匹配标签前缀
				// 为了效率，我们只保留最后 10 个字符作为 buffer 如果它包含 '<'
				parseLimit := 0
				if len(contentBuffer) > 20 {
					parseLimit = len(contentBuffer) - 20
				}
				lastOpen := strings.LastIndexByte(contentBuffer[parseLimit:], '<')
				if lastOpen != -1 {
					// 实际上这里需要更严谨，但只要保留末尾一段即可
					cutoff = parseLimit + lastOpen
					possibleTag = true
				} else {
					// 没有 '<'，说明前面全是普通文本（或者已经在 thinking 里面了）
					// 等等，我们在 thinking 里面也可能遇到 </think>，所以也要找 '<'
				}

				if !possibleTag {
					// 全部输出
					if contentBuffer != "" {
						emitDelta(contentBuffer)
						contentBuffer = ""
					}
				} else {
					// 输出 safe 部分
					safePart := contentBuffer[:cutoff]
					if safePart != "" {
						emitDelta(safePart)
					}
					contentBuffer = contentBuffer[cutoff:]
				}
				break // 等待更多数据
			}

			// 找到了标签，处理最早出现的那个
			var tagIdx int
			var isStartTag bool

			if startTagIdx != -1 && (endTagIdx == -1 || startTagIdx < endTagIdx) {
				tagIdx = startTagIdx
				isStartTag = true
			} else {
				tagIdx = endTagIdx
				isStartTag = false
			}

			// 输出标签前的内容
			preText := contentBuffer[:tagIdx]
			if preText != "" {
				emitDelta(preText)
			}

			// 切换状态
			if isStartTag {
				// 遇到 <think>，切换到 thinking 模式
				// 如果之前是 text，先结束
				if currentBlockType == "text" {
					w.Write([]byte(fmt.Sprintf("event: content_block_stop\ndata: {\"type\": \"content_block_stop\", \"index\": %d}\n\n", currentBlockIdx)))
				}
				// 只有当不是 thinking 时才开启新块 (或者之前的 thinking 已结束)
				if currentBlockType != "thinking" {
					currentBlockIdx++
					currentBlockType = "thinking"
					w.Write([]byte(fmt.Sprintf("event: content_block_start\ndata: {\"type\": \"content_block_start\", \"index\": %d, \"content_block\": {\"type\": \"thinking\", \"thinking\": \"\"}}\n\n", currentBlockIdx)))
				}
				// 消耗标签
				contentBuffer = contentBuffer[tagIdx+7:]
			} else {
				// 遇到 </think>，切换回 text 模式
				// 如果之前是 thinking，先结束
				if currentBlockType == "thinking" {
					w.Write([]byte(fmt.Sprintf("event: content_block_stop\ndata: {\"type\": \"content_block_stop\", \"index\": %d}\n\n", currentBlockIdx)))
				}
				// 只有当不是 text 时才开启新块
				if currentBlockType != "text" {
					currentBlockIdx++
					currentBlockType = "text"
					w.Write([]byte(fmt.Sprintf("event: content_block_start\ndata: {\"type\": \"content_block_start\", \"index\": %d, \"content_block\": {\"type\": \"text\", \"text\": \"\"}}\n\n", currentBlockIdx)))
				}
				// 消耗标签
				contentBuffer = contentBuffer[tagIdx+8:]
			}
		}

		flusher.Flush()
	}
}

func init() {
	// 在此处设置日志前缀以便调试
	log.SetPrefix("[ant2oa] ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
