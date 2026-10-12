import { useState } from 'react';
import { motion } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Copy, Check, Database, AlertTriangle, Scissors, Square } from 'lucide-react';
import './ChatMessage.css';

/** Copies text, with a fallback for plain-HTTP pages where navigator.clipboard is unavailable. */
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // fall through to the legacy method
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  const ok = document.execCommand('copy');
  document.body.removeChild(area);
  return ok;
}

function CopyButton({ text, label = 'Copy', className = '' }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className={`msg-action-btn ${className}`}
      onClick={async () => {
        if (await copyText(text)) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        }
      }}
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied' : label}
    >
      {copied ? <Check size={14} /> : <Copy size={14} />}
      <span>{copied ? 'Copied' : label}</span>
    </button>
  );
}

function CodeBlock({ language, code }) {
  return (
    <div className="md-code-block">
      <div className="md-code-header">
        <span>{language || 'text'}</span>
        <CopyButton text={code} label="Copy code" className="md-code-copy" />
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

const markdownComponents = {
  // Fenced code blocks: react-markdown renders <pre><code class="language-x">.
  pre({ children }) {
    const child = Array.isArray(children) ? children[0] : children;
    const className = child?.props?.className || '';
    const language = /language-([\w+#-]+)/.exec(className)?.[1];
    const code = String(child?.props?.children ?? '').replace(/\n$/, '');
    return <CodeBlock language={language} code={code} />;
  },
  a({ href, children }) {
    return <a href={href} target="_blank" rel="noopener noreferrer nofollow">{children}</a>;
  },
  table({ children }) {
    return <div className="md-table-wrap"><table>{children}</table></div>;
  }
};

/**
 * Markdown from the model, rendered safely: no raw HTML (react-markdown's default), javascript: and
 * other unsafe links stripped (default URL transform), and no images. A model-written image URL
 * would be fetched automatically by the browser, which can leak conversation content to any host.
 */
export function Markdown({ text }) {
  return (
    <div className="md">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents} disallowedElements={['img']}>
        {text}
      </ReactMarkdown>
    </div>
  );
}

/**
 * message: { role, text, isStreaming, isError, truncated, stopped, suggestSearch, question, isWelcome }
 * badge: optional label shown next to the assistant name (e.g. "Searched Wazuh").
 * status: while streaming, what the backend is actually doing (a Search Wazuh stage); shown in the
 *   message column, in place of "Thinking…" before any text arrives and under the text after.
 */
export default function ChatMessage({ message, badge, onSearchWazuh, status }) {
  const isUser = message.role === 'user';
  const text = message.text || '';
  const thinking = message.isStreaming && !text;
  const showActions = !isUser && !message.isStreaming && !message.isWelcome && !message.isError && text;

  return (
    <motion.div
      className={`chat-message-row ${isUser ? 'row-user' : 'row-bot'}`}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
    >
      <div className="chat-message-container">
        <div className={`chat-content ${isUser ? 'content-user' : 'content-bot'}`}>
          {!isUser && (
            <span className="assistant-label">
              SOC Assistant
              {badge && <span className="assistant-badge"><Database size={11} />{badge}</span>}
            </span>
          )}

          {isUser ? (
            <div className="message-bubble">{text}</div>
          ) : thinking ? (
            <div className="typing-status" role="status">
              <span className="typing-spinner" />
              <span className="typing-status-text">{status || 'Thinking…'}</span>
            </div>
          ) : message.isError ? (
            <div className="msg-notice msg-notice-error" role="alert">
              <AlertTriangle size={15} />
              <span>{text}</span>
            </div>
          ) : (
            <div className={`message-text ${message.isStreaming ? 'is-streaming' : ''}`}>
              <Markdown text={text} />
              {message.isStreaming && !status && <span className="stream-cursor" aria-hidden="true" />}
            </div>
          )}

          {!isUser && message.isStreaming && status && text && (
            <div className="typing-status" role="status">
              <span className="typing-spinner" />
              <span className="typing-status-text">{status}</span>
            </div>
          )}

          {!isUser && !message.isStreaming && message.errorNotice && (
            <div className="msg-notice msg-notice-warning" role="alert">
              <AlertTriangle size={15} />
              <span>{message.errorNotice}</span>
            </div>
          )}
          {!isUser && !message.isStreaming && message.stopped && (
            <div className="msg-notice"><Square size={12} /><span>Stopped. This answer is incomplete.</span></div>
          )}
          {!isUser && !message.isStreaming && message.truncated && !message.errorNotice && !message.stopped && (
            <div className="msg-notice msg-notice-warning"><Scissors size={14} /><span>This answer was cut off at the length limit. Ask “continue” for the rest.</span></div>
          )}

          {showActions && (
            <div className="msg-actions">
              <CopyButton text={text} />
              {message.suggestSearch && onSearchWazuh && message.question && (
                <button type="button" className="msg-action-btn msg-action-primary" onClick={() => onSearchWazuh(message.question)}>
                  <Database size={14} />
                  <span>Search Wazuh for this</span>
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </motion.div>
  );
}

