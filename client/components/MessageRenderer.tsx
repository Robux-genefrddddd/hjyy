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
  const { isDark } = useTheme();
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className={`my-3 rounded-lg overflow-hidden border shadow-lg hover:shadow-xl transition-all duration-300 ${
        isDark ? "border-white/10" : "border-black/[0.08]"
      }`}
      style={{
        backgroundColor: isDark ? "#0f1117" : "#F5F5F5",
      }}
    >
      <div
        className="flex items-center justify-between px-4 py-3 border-b transition-all duration-300"
        style={{
          backgroundColor: isDark
            ? "rgba(88, 166, 255, 0.1)"
            : "rgba(59, 130, 246, 0.05)",
          borderColor: isDark
            ? "rgba(255, 255, 255, 0.1)"
            : "rgba(0, 0, 0, 0.08)",
        }}
      >
        <span
          className={`text-xs font-mono font-semibold uppercase tracking-wide transition-colors duration-300 ${
            isDark ? "text-orange-300" : "text-orange-600"
          }`}
        >
          {language || "code"}
        </span>
        <button
          onClick={handleCopy}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all duration-200 hover:shadow-md ${
            isDark
              ? "bg-white/10 hover:bg-white/20 text-white/70 hover:text-white"
              : "bg-black/[0.08] hover:bg-black/[0.12] text-[#3F3F3F] hover:text-[#1A1A1A]"
          }`}
          title="Copier le code"
        >
          {copied ? (
            <>
              <Check
                size={14}
                className={isDark ? "text-green-400" : "text-green-600"}
              />
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
        <code
          className={`font-mono text-sm leading-[1.55] whitespace-pre transition-colors duration-300 ${
            isDark ? "text-white/90" : "text-[#1A1A1A]/90"
          }`}
        >
          {escapeHtml(code)}
        </code>
      </pre>
    </div>
  );
}

function parseMarkdownElements(text: string, isDark: boolean): ReactNode[] {
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
        h1: "text-3xl font-bold mb-4 mt-6 border-b pb-2",
        h2: "text-2xl font-bold mb-3 mt-5 border-b pb-2",
        h3: "text-xl font-bold mb-2 mt-4",
        h4: "text-lg font-bold mb-2 mt-3",
        h5: "text-base font-bold mb-2 mt-2",
        h6: "text-sm font-bold mb-2 mt-2",
      };

      const HeadingElement = HeadingTag;
      elements.push(
        <HeadingElement
          key={`h-${i}`}
          className={`leading-[1.55] transition-all duration-300 ${
            isDark
              ? "text-white border-white/20"
              : "text-[#1A1A1A] border-black/[0.08]"
          } ${headingClasses[HeadingTag]}`}
        >
          {parseInlineMarkdown(content, isDark)}
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
          className={`border-l-4 border-orange-500 pl-4 py-2 my-3 italic rounded-r-lg leading-[1.55] transition-all duration-300 ${
            isDark ? "text-white/70" : "text-[#3F3F3F]/70"
          }`}
          style={{
            backgroundColor: isDark
              ? "rgba(88, 166, 255, 0.08)"
              : "rgba(59, 130, 246, 0.05)",
          }}
        >
          {parseInlineMarkdown(quoteText, isDark)}
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
            className={`list-decimal list-inside mb-3 space-y-2 pl-2 transition-all duration-300 ${
              isDark ? "text-white/90" : "text-[#1A1A1A]/90"
            }`}
          >
            {listItems.map((item, idx) => (
              <li
                key={idx}
                className={`leading-[1.55] transition-all duration-300 ${
                  isDark ? "text-white/90" : "text-[#1A1A1A]/90"
                }`}
              >
                {parseInlineMarkdown(item, isDark)}
              </li>
            ))}
          </ol>,
        );
      } else {
        elements.push(
          <ul
            key={`ul-${i}`}
            className={`list-disc list-inside mb-3 space-y-2 pl-2 transition-all duration-300 ${
              isDark ? "text-white/90" : "text-[#1A1A1A]/90"
            }`}
          >
            {listItems.map((item, idx) => (
              <li
                key={idx}
                className={`leading-[1.55] transition-all duration-300 ${
                  isDark ? "text-white/90" : "text-[#1A1A1A]/90"
                }`}
              >
                {parseInlineMarkdown(item, isDark)}
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
        <p
          key={`p-${i}`}
          className={`mb-3 leading-[1.55] transition-all duration-300 ${
            isDark ? "text-white/90" : "text-[#1A1A1A]/90"
          }`}
        >
          {parseInlineMarkdown(trimmed, isDark)}
        </p>,
      );
    }

    i++;
  }

  return elements;
}

function parseInlineMarkdown(text: string, isDark: boolean): ReactNode[] {
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
          <strong
            key={idx}
            className={`font-bold transition-colors duration-300 ${
              isDark ? "text-white" : "text-[#1A1A1A]"
            }`}
          >
            {escapeHtml(m.content)}
          </strong>,
        );
        break;
      case "italic":
        parts.push(
          <em
            key={idx}
            className={`italic transition-colors duration-300 ${
              isDark ? "text-white/95" : "text-[#1A1A1A]/95"
            }`}
          >
            {escapeHtml(m.content)}
          </em>,
        );
        break;
      case "code":
        parts.push(
          <code
            key={idx}
            className={`px-2 py-1 rounded font-mono text-sm border font-semibold transition-all duration-300 ${
              isDark
                ? "bg-white/15 text-orange-300 border-white/10"
                : "bg-orange-100/50 text-orange-700 border-orange-200"
            }`}
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
            className={`underline font-medium transition-colors duration-300 ${
              isDark
                ? "text-orange-400 hover:text-orange-300"
                : "text-orange-600 hover:text-orange-700"
            }`}
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
  const { isDark } = useTheme();

  // Check if content is an image URL
  const imageUrlPattern = /^https?:\/\/[^\s]+\.(jpg|jpeg|png|gif|webp|svg)$/i;
  const isImageUrl = imageUrlPattern.test(content.trim());

  if (isImageUrl) {
    return (
      <div className="flex justify-center">
        <div
          className={`rounded-3xl overflow-hidden border-2 shadow-lg max-w-xs transition-all duration-300 ${
            isDark ? "border-white/20" : "border-black/[0.08]"
          }`}
        >
          <img
            src={content}
            alt="Message content"
            className="w-full h-auto object-cover"
          />
        </div>
      </div>
    );
  }

  const elements = parseMarkdownElements(content, isDark);

  return (
    <div>
      {elements}
      {isStreaming && (
        <span
          className={`inline-block w-2 h-5 ml-1 animate-pulse transition-colors duration-300 ${
            isDark ? "bg-white/50" : "bg-[#3F3F3F]/50"
          }`}
        />
      )}
    </div>
  );
}
