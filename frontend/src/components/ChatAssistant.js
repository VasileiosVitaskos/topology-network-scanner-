import React, { useState, useRef, useEffect } from 'react';
import api from '../services/api';

export default function ChatAssistant() {
  const [messages, setMessages] = useState([
    { role: 'system', content: 'Security assistant ready. Run a scan or ask about network threats.' }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const endRef = useRef(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim()) return;
    const userMsg = input;
    setMessages(prev => [...prev, { role: 'user', content: userMsg }]);
    setInput('');
    setLoading(true);
    try {
      const res = await api.askAssistant(userMsg);
      setMessages(prev => [...prev, {
        role: 'system',
        content: res.response || res.error || 'No response.',
      }]);
    } catch (e) {
      setMessages(prev => [...prev, {
        role: 'system',
        content: 'Connection to AI backend failed.',
      }]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="chat-container">
      <div className="panel-header">AI Assistant</div>
      <div className="chat-history">
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg ${m.role}`}>
            {m.content}
          </div>
        ))}
        {loading && <div className="chat-msg system">Analyzing...</div>}
        <div ref={endRef} />
      </div>
      <div className="chat-input-area">
        <input
          type="text"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !loading && handleSend()}
          placeholder="Ask about threats, topology, or recommendations..."
          className="chat-input"
          disabled={loading}
        />
        <button onClick={handleSend} disabled={loading || !input.trim()} className="chat-send-btn">
          Send
        </button>
      </div>
    </div>
  );
}