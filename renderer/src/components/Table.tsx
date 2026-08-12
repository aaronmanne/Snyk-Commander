import React, { useState } from 'react'
import { ChevronUp, ChevronDown } from 'lucide-react'

export interface Column<T> {
  key: string
  header: string
  sortable?: boolean
  render?: (row: T, index: number) => React.ReactNode
  className?: string
}

interface TableProps<T> {
  columns: Column<T>[]
  data: T[]
  keyExtractor: (row: T, index: number) => string
  onRowClick?: (row: T) => void
  expandedRowKey?: string | null
  renderExpanded?: (row: T) => React.ReactNode
  emptyMessage?: string
  className?: string
}

type SortDir = 'asc' | 'desc' | null

export default function Table<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  expandedRowKey,
  renderExpanded,
  emptyMessage = 'No data to display',
  className = '',
}: TableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<SortDir>(null)

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : d === 'desc' ? null : 'asc')
      if (sortDir === 'desc') setSortKey(null)
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const sortedData = [...data].sort((a, b) => {
    if (!sortKey || !sortDir) return 0
    const col = columns.find(c => c.key === sortKey)
    if (!col) return 0
    const aVal = (a as Record<string, unknown>)[sortKey]
    const bVal = (b as Record<string, unknown>)[sortKey]
    const cmp = String(aVal ?? '').localeCompare(String(bVal ?? ''), undefined, { numeric: true })
    return sortDir === 'asc' ? cmp : -cmp
  })

  return (
    <div className={`w-full overflow-auto ${className}`}>
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border">
            {columns.map(col => (
              <th
                key={col.key}
                className={`px-4 py-3 text-left text-text-muted font-medium whitespace-nowrap ${col.className ?? ''} ${col.sortable ? 'cursor-pointer select-none hover:text-text-primary transition-colors' : ''}`}
                onClick={col.sortable ? () => handleSort(col.key) : undefined}
              >
                <div className="flex items-center gap-1">
                  {col.header}
                  {col.sortable && (
                    <span className="flex flex-col ml-1">
                      <ChevronUp
                        size={10}
                        className={sortKey === col.key && sortDir === 'asc' ? 'text-accent-purple' : 'text-text-muted opacity-40'}
                      />
                      <ChevronDown
                        size={10}
                        className={sortKey === col.key && sortDir === 'desc' ? 'text-accent-purple' : 'text-text-muted opacity-40'}
                      />
                    </span>
                  )}
                </div>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedData.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-12 text-center text-text-muted">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            sortedData.map((row, idx) => {
              const key = keyExtractor(row, idx)
              const isExpanded = expandedRowKey === key
              return (
                <React.Fragment key={key}>
                  <tr
                    className={`border-b border-border/50 table-row-hover transition-colors ${onRowClick ? 'cursor-pointer' : ''} ${isExpanded ? 'bg-accent-purple/5' : ''}`}
                    onClick={() => onRowClick?.(row)}
                  >
                    {columns.map(col => (
                      <td
                        key={col.key}
                        className={`px-4 py-3 text-text-primary ${col.className ?? ''}`}
                      >
                        {col.render ? col.render(row, idx) : String((row as Record<string, unknown>)[col.key] ?? '')}
                      </td>
                    ))}
                  </tr>
                  {isExpanded && renderExpanded && (
                    <tr className="bg-bg-tertiary/50">
                      <td colSpan={columns.length} className="px-4 py-4">
                        {renderExpanded(row)}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              )
            })
          )}
        </tbody>
      </table>
    </div>
  )
}
