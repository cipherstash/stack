/**
 * Render agent markdown output as styled terminal text.
 *
 * Uses picocolors (already a transitive dep of @clack/prompts)
 * for lightweight ANSI styling — no extra dependencies needed.
 */

import pc from 'picocolors'

/**
 * Format markdown-ish agent output for the terminal.
 *
 * Handles: headings, bold, checkmarks/bullets, code blocks,
 * inline code, and numbered lists.
 */
export function formatAgentOutput(text: string): string {
  const lines = text.split('\n')
  const result: string[] = []
  let inCodeBlock = false

  for (const line of lines) {
    // Code block fences
    if (line.trimStart().startsWith('```')) {
      inCodeBlock = !inCodeBlock
      if (inCodeBlock) {
        // Opening fence — show a dim border
        result.push(pc.dim('  ┌─────────────────────────────────'))
      } else {
        result.push(pc.dim('  └─────────────────────────────────'))
      }
      continue
    }

    // Inside code block — dim + indented
    if (inCodeBlock) {
      result.push(pc.dim(`  │ ${line}`))
      continue
    }

    // Headings
    if (line.startsWith('## ')) {
      result.push('')
      result.push(pc.bold(pc.cyan(line.replace(/^##\s+/, ''))))
      result.push('')
      continue
    }
    if (line.startsWith('# ')) {
      result.push('')
      result.push(pc.bold(pc.cyan(line.replace(/^#\s+/, ''))))
      result.push('')
      continue
    }

    // Checkmark lines: ✅ or - ✅ or * ✅
    if (/^\s*[-*]?\s*✅/.test(line)) {
      const content = line.replace(/^\s*[-*]?\s*✅\s*/, '')
      result.push(`  ${pc.green('✔')} ${formatInline(content)}`)
      continue
    }

    // Bullet points with bold label: - **label** — rest
    const bulletBoldMatch = line.match(
      /^\s*[-*]\s+\*\*(.+?)\*\*\s*[-—:]?\s*(.*)/,
    )
    if (bulletBoldMatch) {
      const [, label, rest] = bulletBoldMatch
      result.push(
        `  ${pc.dim('•')} ${pc.bold(label)}${rest ? pc.dim(' — ') + rest : ''}`,
      )
      continue
    }

    // Plain bullet points
    if (/^\s*[-*]\s+/.test(line)) {
      const content = line.replace(/^\s*[-*]\s+/, '')
      result.push(`  ${pc.dim('•')} ${formatInline(content)}`)
      continue
    }

    // Numbered lists
    const numberedMatch = line.match(/^\s*(\d+)\.\s+(.*)/)
    if (numberedMatch) {
      const [, num, content] = numberedMatch
      result.push(`  ${pc.dim(`${num}.`)} ${formatInline(content)}`)
      continue
    }

    // Regular text
    result.push(formatInline(line))
  }

  // Close unclosed code block
  if (inCodeBlock) {
    result.push(pc.dim('  └─────────────────────────────────'))
  }

  return result.join('\n')
}

/**
 * Format inline markdown: **bold**, `code`, and links.
 */
function formatInline(text: string): string {
  return (
    text
      // Bold
      .replace(/\*\*(.+?)\*\*/g, (_, content) => pc.bold(content))
      // Inline code
      .replace(/`([^`]+)`/g, (_, content) => pc.cyan(content))
      // Links [text](url) — show text, dim the URL
      .replace(
        /\[([^\]]+)\]\(([^)]+)\)/g,
        (_, linkText, url) => `${pc.underline(linkText)} ${pc.dim(`(${url})`)}`,
      )
  )
}
