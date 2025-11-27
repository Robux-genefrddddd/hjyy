import { Copy, Check } from "lucide-react";
import { useState, ReactNode } from "react";
import { escapeHtml } from "@/lib/security";
import { useTheme } from "@/contexts/ThemeContext";

interface MessageRendererProps {
  content: string;
  role: "user" | "assistant";
  isStreaming?: boolean;
}

function CodeBlockWithCopy({
  language,
  code,
}: {
  language: string;
  code: string;
}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="my-3 rounded-lg overflow-hidden border border-white/10 shadow-lg hover:shadow-xl transition-shadow"
      style={{ backgroundColor: "#0f1117" }}
    >
      <div
        className="flex items-center justify-between px-4 py-3 border-b border-white/10"
        style={{ backgroundColor: "rgba(88, 166, 255, 0.1)" }}
      >
        <span className="text-xs font-mono text-orange-300 font-semibold uppercase tracking-wide">
          {language || "code"}
        </span>
        <button
          onClick={handleCopy}
          className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-white/10 hover:bg-white/20 text-white/70 hover:text-white text-xs font-medium transition-all duration-200 hover:shadow-md"
          title="Copier le code"
        >
          {copied ? (
            <>
              <Check size={14} className="text-green-400" />
              <span>Copié!</span>
            </>
          ) : (
            <>
              <Copy size={14} />
              <span>Copier</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-4 overflow-x-auto">
        <code className="font-mono text-sm leading-[1.55] text-white/90 whitespace-pre">
          {escapeHtml(code)}
        </code>
      </pre>
    </div>
  );
}

function parseMarkdownElements(text: string): ReactNode[] {
  const lines = text.split("\n");
  const elements: ReactNode[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    // Code blocks
    if (trimmed.startsWith("```")) {
      const lang = trimmed.slice(3).trim();
      let code = "";
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        code += lines[i] + "\n";
        i++;
      }
      elements.push(
        <CodeBlockWithCopy
          key={`code-${i}`}
          language={lang}
          code={code.trim()}
        />,
      );
      i++;
      continue;
    }

    // Headers
    const headerMatch = trimmed.match(/^(#{1,6})\s+(.*)$/);
    if (headerMatch) {
      const level = headerMatch[1].length;
      const content = headerMatch[2];
      const HeadingTag = `h${level}` as const;
      const headingClasses = {
        h1: "text-3xl font-bold mb-4 mt-6 border-b border-white/20 pb-2",
        h2: "text-2xl font-bold mb-3 mt-5 border-b border-white/10 pb-2",
        h3: "text-xl font-bold mb-2 mt-4",
        h4: "text-lg font-bold mb-2 mt-3",
        h5: "text-base font-bold mb-2 mt-2",
        h6: "text-sm font-bold mb-2 mt-2",
      };

      const HeadingElement = HeadingTag;
      elements.push(
        <HeadingElement
          key={`h-${i}`}
          className={`text-white leading-[1.55] ${headingClasses[HeadingTag]}`}
        >
          {parseInlineMarkdown(content)}
        </HeadingElement>,
      );
      i++;
      continue;
    }

    // Blockquotes
    if (trimmed.startsWith(">")) {
      let quoteText = trimmed.slice(1).trim();
      i++;
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        quoteText += " " + lines[i].trim().slice(1).trim();
        i++;
      }
      elements.push(
        <blockquote
          key={`quote-${i}`}
          className="border-l-4 border-orange-500 pl-4 py-2 my-3 text-white/70 italic rounded-r-lg leading-[1.55]"
          style={{ backgroundColor: "rgba(88, 166, 255, 0.08)" }}
        >
          {parseInlineMarkdown(quoteText)}
        </blockquote>,
      );
      continue;
    }

    // Lists
    if (trimmed.match(/^[\*\-\+]\s+/) || trimmed.match(/^\d+\.\s+/)) {
      const isOrdered = !!trimmed.match(/^\d+\.\s+/);
      const listItems: string[] = [];

      while (
        i < lines.length &&
        (lines[i].trim().match(/^[\*\-\+]\s+/) ||
          lines[i].trim().match(/^\d+\.\s+/))
      ) {
        listItems.push(
          lines[i]
            .trim()
            .replace(/^[\*\-\+]\s+/, "")
            .replace(/^\d+\.\s+/, ""),
        );
        i++;
      }

      if (isOrdered) {
        elements.push(
          <ol
            key={`ol-${i}`}
            className="list-decimal list-inside mb-3 space-y-2 text-white/90 pl-2"
          >
            {listItems.map((item, idx) => (
              <li key={idx} className="text-white/90 leading-[1.55]">
                {parseInlineMarkdown(item)}
              </li>
            ))}
          </ol>,
        );
      } else {
        elements.push(
          <ul
            key={`ul-${i}`}
            className="list-disc list-inside mb-3 space-y-2 text-white/90 pl-2"
          >
            {listItems.map((item, idx) => (
              <li key={idx} className="text-white/90 leading-[1.55]">
                {parseInlineMarkdown(item)}
              </li>
            ))}
          </ul>,
        );
      }
      continue;
    }

    // Regular paragraphs
    if (trimmed) {
      elements.push(
        <p key={`p-${i}`} className="mb-3 leading-[1.55] text-white/90">
          {parseInlineMarkdown(trimmed)}
        </p>,
      );
    }

    i++;
  }

  return elements;
}

function parseInlineMarkdown(text: string): ReactNode[] {
  const parts: ReactNode[] = [];
  let lastIndex = 0;

  // Bold (**text** or __text__)
  const boldRegex = /\*\*(.+?)\*\*|__(.+?)__/g;
  let match;

  // Process all inline formatting
  const allMatches: Array<{
    type: string;
    start: number;
    end: number;
    content: string;
  }> = [];

  // Bold
  const boldRe = /\*\*(.+?)\*\*|__(.+?)__/g;
  while ((match = boldRe.exec(text))) {
    allMatches.push({
      type: "bold",
      start: match.index,
      end: match.index + match[0].length,
      content: match[1] || match[2],
    });
  }

  // Italic
  const italicRe = /\*(.+?)\*|_(.+?)_/g;
  while ((match = italicRe.exec(text))) {
    // Skip if it's part of bold
    const isBold = allMatches.some(
      (m) =>
        m.type === "bold" &&
        m.start <= match.index &&
        match.index + match[0].length <= m.end,
    );
    if (!isBold) {
      allMatches.push({
        type: "italic",
        start: match.index,
        end: match.index + match[0].length,
        content: match[1] || match[2],
      });
    }
  }

  // Inline code
  const codeRe = /`(.+?)`/g;
  while ((match = codeRe.exec(text))) {
    allMatches.push({
      type: "code",
      start: match.index,
      end: match.index + match[0].length,
      content: match[1],
    });
  }

  // Links
  const linkRe = /\[(.+?)\]\((.+?)\)/g;
  while ((match = linkRe.exec(text))) {
    allMatches.push({
      type: "link",
      start: match.index,
      end: match.index + match[0].length,
      content: match[1],
      url: match[2],
    });
  }

  // Sort by position
  allMatches.sort((a, b) => a.start - b.start);

  // Render with formatting
  allMatches.forEach((m, idx) => {
    if (m.start > lastIndex) {
      // Escape plain text to prevent XSS
      parts.push(escapeHtml(text.substring(lastIndex, m.start)));
    }

    switch (m.type) {
      case "bold":
        parts.push(
          <strong key={idx} className="font-bold text-white">
            {escapeHtml(m.content)}
          </strong>,
        );
        break;
      case "italic":
        parts.push(
          <em key={idx} className="italic text-white/95">
            {escapeHtml(m.content)}
          </em>,
        );
        break;
      case "code":
        parts.push(
          <code
            key={idx}
            className="bg-white/15 px-2 py-1 rounded font-mono text-sm text-orange-300 border border-white/10 font-semibold"
          >
            {escapeHtml(m.content)}
          </code>,
        );
        break;
      case "link":
        parts.push(
          <a
            key={idx}
            href={m.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-orange-400 hover:text-orange-300 underline font-medium transition-colors"
          >
            {escapeHtml(m.content)}
          </a>,
        );
        break;
      default:
        break;
    }

    lastIndex = m.end;
  });

  if (lastIndex < text.length) {
    // Escape remaining plain text to prevent XSS
    parts.push(escapeHtml(text.substring(lastIndex)));
  }

  return parts.length > 0 ? parts : [escapeHtml(text)];
}

export function MessageRenderer({
  content,
  role,
  isStreaming = false,
}: MessageRendererProps) {
  // Check if content is an image URL
  const imageUrlPattern = /^https?:\/\/[^\s]+\.(jpg|jpeg|png|gif|webp|svg)$/i;
  const isImageUrl = imageUrlPattern.test(content.trim());

  if (isImageUrl) {
    return (
      <div className="flex justify-center">
        <div className="rounded-3xl overflow-hidden border-2 border-white/20 shadow-lg max-w-xs">
          <img
            src={content}
            alt="Message content"
            className="w-full h-auto object-cover"
          />
        </div>
      </div>
    );
  }

  const elements = parseMarkdownElements(content);

  return (
    <div>
      {elements}
      {isStreaming && (
        <span className="inline-block w-2 h-5 bg-white/50 ml-1 animate-pulse" />
      )}
    </div>
  );
}
