import React from 'react'

interface Props {
  content: string
  className?: string
}

/**
 * Lightweight markdown renderer — no external dependencies.
 * Handles: headings, bold, italic, inline code, code blocks,
 * tables, horizontal rules, blockquotes, ordered/unordered lists, links.
 */
export default function MarkdownRenderer({ content, className = '' }: Props) {
  const lines = content.split('\n')
  const elements: React.ReactNode[] = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]

    // ── Fenced code block ─────────────────────────────────────────────────────
    if (line.trimStart().startsWith('```')) {
      const lang = line.trim().slice(3).trim()
      const codeLines: string[] = []
      i++
      while (i < lines.length && !lines[i].trimStart().startsWith('```')) {
        codeLines.push(lines[i])
        i++
      }
      elements.push(
        <pre key={i} className="my-3 p-3 bg-bg-tertiary border border-border rounded-lg overflow-x-auto">
          {lang && <div className="text-xs text-text-muted mb-1 font-mono">{lang}</div>}
          <code className="text-xs font-mono text-text-secondary leading-relaxed whitespace-pre">
            {codeLines.join('\n')}
          </code>
        </pre>
      )
      i++
      continue
    }

    // ── Horizontal rule ───────────────────────────────────────────────────────
    if (/^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim())) {
      elements.push(<hr key={i} className="my-4 border-border" />)
      i++
      continue
    }

    // ── Headings ──────────────────────────────────────────────────────────────
    const h4 = line.match(/^####\s+(.+)/)
    const h3 = line.match(/^###\s+(.+)/)
    const h2 = line.match(/^##\s+(.+)/)
    const h1 = line.match(/^#\s+(.+)/)
    if (h4) { elements.push(<h4 key={i} className="text-xs font-semibold text-text-primary mt-4 mb-1 uppercase tracking-wider text-text-muted">{inline(h4[1])}</h4>); i++; continue }
    if (h3) { elements.push(<h3 key={i} className="text-sm font-semibold text-text-primary mt-4 mb-1.5">{inline(h3[1])}</h3>); i++; continue }
    if (h2) { elements.push(<h2 key={i} className="text-base font-bold text-text-primary mt-5 mb-2 pb-1 border-b border-border">{inline(h2[1])}</h2>); i++; continue }
    if (h1) { elements.push(<h1 key={i} className="text-lg font-bold text-text-primary mt-5 mb-2">{inline(h1[1])}</h1>); i++; continue }

    // ── Blockquote ────────────────────────────────────────────────────────────
    if (line.startsWith('> ')) {
      const quoteLines: string[] = []
      while (i < lines.length && lines[i].startsWith('> ')) {
        quoteLines.push(lines[i].slice(2))
        i++
      }
      elements.push(
        <blockquote key={i} className="border-l-2 border-accent-purple pl-3 my-3 text-text-secondary text-sm italic">
          {quoteLines.map((ql, qi) => <p key={qi} className="leading-relaxed">{inline(ql)}</p>)}
        </blockquote>
      )
      continue
    }

    // ── Table ─────────────────────────────────────────────────────────────────
    if (line.includes('|') && lines[i + 1]?.match(/^\|?[\s\-|:]+\|?$/)) {
      const headers = parseCells(line)
      i += 2 // skip separator
      const rows: string[][] = []
      while (i < lines.length && lines[i].includes('|')) {
        rows.push(parseCells(lines[i]))
        i++
      }
      elements.push(
        <div key={i} className="my-3 overflow-x-auto">
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="border-b border-border">
                {headers.map((h, hi) => (
                  <th key={hi} className="px-3 py-1.5 text-left text-text-secondary font-semibold">{inline(h)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, ri) => (
                <tr key={ri} className="border-b border-border/40 hover:bg-bg-tertiary/40">
                  {row.map((cell, ci) => (
                    <td key={ci} className="px-3 py-1.5 text-text-secondary">{inline(cell)}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )
      continue
    }

    // ── Unordered list ────────────────────────────────────────────────────────
    if (/^[\s]*[-*+]\s/.test(line)) {
      const items: Array<{ text: string; depth: number }> = []
      while (i < lines.length && /^[\s]*[-*+]\s/.test(lines[i])) {
        const depth = lines[i].match(/^(\s*)/)?.[1].length ?? 0
        items.push({ text: lines[i].replace(/^\s*[-*+]\s/, ''), depth })
        i++
      }
      elements.push(
        <ul key={i} className="my-2 space-y-1">
          {items.map((item, ii) => (
            <li key={ii} className="flex gap-2 text-sm text-text-secondary leading-relaxed"
                style={{ paddingLeft: `${item.depth * 12}px` }}>
              <span className="text-accent-purple mt-1 flex-shrink-0">•</span>
              <span>{inline(item.text)}</span>
            </li>
          ))}
        </ul>
      )
      continue
    }

    // ── Ordered list ──────────────────────────────────────────────────────────
    if (/^\d+\.\s/.test(line)) {
      const items: string[] = []
      while (i < lines.length && /^\d+\.\s/.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\.\s/, ''))
        i++
      }
      elements.push(
        <ol key={i} className="my-2 space-y-1 list-none">
          {items.map((item, ii) => (
            <li key={ii} className="flex gap-2 text-sm text-text-secondary leading-relaxed">
              <span className="text-accent-purple font-mono flex-shrink-0 w-5 text-right">{ii + 1}.</span>
              <span>{inline(item)}</span>
            </li>
          ))}
        </ol>
      )
      continue
    }

    // ── Empty line ────────────────────────────────────────────────────────────
    if (line.trim() === '') {
      elements.push(<div key={i} className="h-2" />)
      i++
      continue
    }

    // ── Paragraph ─────────────────────────────────────────────────────────────
    elements.push(
      <p key={i} className="text-sm text-text-secondary leading-relaxed my-1">
        {inline(line)}
      </p>
    )
    i++
  }

  return (
    <div className={`markdown-content ${className}`}>
      {elements}
    </div>
  )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function parseCells(row: string): string[] {
  return row.split('|').map(c => c.trim()).filter((c, i, arr) => {
    // Remove leading/trailing empty cells from | col | col | pattern
    if (i === 0 && c === '') return false
    if (i === arr.length - 1 && c === '') return false
    return true
  })
}

/** Render inline markdown: bold, italic, inline code, links */
function inline(text: string): React.ReactNode {
  if (!text) return null
  // Split on inline patterns
  const parts = splitInline(text)
  if (parts.length === 1 && typeof parts[0] === 'string') return parts[0]
  return <>{parts}</>
}

function splitInline(text: string): React.ReactNode[] {
  const result: React.ReactNode[] = []
  // Combined regex: **bold**, *italic*, `code`, [link](url)
  const re = /(\*\*(.+?)\*\*|\*(.+?)\*|`([^`]+)`|\[([^\]]+)\]\(([^)]+)\))/g
  let last = 0
  let match: RegExpExecArray | null

  while ((match = re.exec(text)) !== null) {
    if (match.index > last) result.push(text.slice(last, match.index))

    if (match[2] !== undefined) {
      // **bold**
      result.push(<strong key={match.index} className="font-semibold text-text-primary">{match[2]}</strong>)
    } else if (match[3] !== undefined) {
      // *italic*
      result.push(<em key={match.index} className="italic text-text-secondary">{match[3]}</em>)
    } else if (match[4] !== undefined) {
      // `code`
      result.push(
        <code key={match.index} className="font-mono text-xs bg-bg-tertiary border border-border/60 px-1 py-0.5 rounded text-accent-purple">
          {match[4]}
        </code>
      )
    } else if (match[5] !== undefined && match[6] !== undefined) {
      // [link](url)
        <a key={match.index} href={match[6]}
           className="text-accent-purple hover:underline"
           onClick={e => { e.preventDefault(); window.open(match![6], '_blank', 'noopener,noreferrer') }}>
          {match[5]}
        </a>
    }
    last = match.index + match[0].length
  }

  if (last < text.length) result.push(text.slice(last))
  return result
}
