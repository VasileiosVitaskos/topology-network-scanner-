import React, { useState, useRef, useEffect, forwardRef, useImperativeHandle } from 'react';
import api from '../services/api';

const ChatAssistant = forwardRef(({ scanResult }, ref) => {
  const [messages, setMessages] = useState([
    {
      role: 'system',
      content: 'OT Security Analyst ready. Run a scan or ask me about your network security.'
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // When scan result changes, notify in chat
  useEffect(() => {
    if (scanResult && scanResult.summary) {
      const status = (scanResult.status || 'CLEAN').replace('_', ' ');
      const type = scanResult.scan_type === 'deep' ? 'Deep Scan' : 'Quick Scan';
      setMessages(prev => [...prev, {
        role: 'system',
        content: `${type} complete — ${status}: ${scanResult.summary}`
      }]);
    }
  }, [scanResult?.scan_id, scanResult?.id]);

  // Expose method for parent to trigger
  useImperativeHandle(ref, () => ({
    addMessage: (role, content) => {
      setMessages(prev => [...prev, { role, content }]);
    }
  }));

  const handleSend = async () => {
    const msg = input.trim();
    if (!msg || loading) return;

    setInput('');
    setMessages(prev => [...prev, { role: 'user', content: msg }]);
    setLoading(true);

    try {
      const res = await api.chat(msg);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: res.response || 'No response received.'
      }]);
    } catch (e) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: `Connection error: ${e.message}. The backend may be starting up.`
      }]);
    } finally {
      setLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Quick action buttons
  const quickActions = [
    'Summarize the last scan',
    'What are the biggest risks?',
    'Explain the topological analysis',
    'Recommend firewall rules',
  ];

  return (
    <div className="chat-section">
      <div className="panel-header">
        <span>AI Security Analyst</span>
        <span className="count" style={{ color: loading ? '#00e5ff' : undefined }}>
          {loading ? 'thinking...' : 'ready'}
        </span>
      </div>

      <div className="chat-messages">
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg ${m.role}`}>
            {m.role === 'assistant' && (
              <div style={{ fontSize: 9, color: '#5f6368', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 1 }}>
                AI Analyst
              </div>
            )}
            <div style={{ whiteSpace: 'pre-wrap' }}>{m.content}</div>
          </div>
        ))}

        {loading && (
          <div className="chat-msg assistant">
            <div style={{ fontSize: 9, color: '#5f6368', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 1 }}>
              AI Analyst
            </div>
            <span className="chat-typing">Analyzing</span>
          </div>
        )}

        {/* Quick actions when no conversation yet */}
        {messages.length <= 1 && !loading && (
          <div style={{ padding: '10px 0' }}>
            <div style={{ fontSize: 10, color: '#5f6368', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>
              Quick Actions
            </div>
            {quickActions.map((action, i) => (
              <button
                key={i}
                onClick={() => { setInput(action); }}
                style={{
                  display: 'block',
                  width: '100%',
                  textAlign: 'left',
                  background: '#151821',
                  border: '1px solid #1e2330',
                  borderRadius: 6,
                  padding: '8px 12px',
                  marginBottom: 4,
                  color: '#bdc1c6',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: 11,
                  cursor: 'pointer',
                }}
              >
                → {action}
              </button>
            ))}
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <div className="chat-input-area">
        <input
          ref={inputRef}
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask about network security..."
          className="chat-input"
          disabled={loading}
        />
        <button
          onClick={handleSend}
          disabled={loading || !input.trim()}
          className="chat-send-btn"
        >
          Send
        </button>
      </div>
    </div>
  );
});

ChatAssistant.displayName = 'ChatAssistant';
export default ChatAssistant;
