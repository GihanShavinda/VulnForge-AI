import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'

export default function RiskTrendChart({
  points,
}: {
  points: { label: string; value: number }[]
}) {
  const ref = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!ref.current) return
    const chart = echarts.init(ref.current)
    chart.setOption({
      backgroundColor: 'transparent',
      tooltip: { trigger: 'axis' },
      grid: { left: 48, right: 18, top: 28, bottom: 38 },
      xAxis: {
        type: 'category',
        data: points.map((point) => point.label),
        axisLabel: { color: '#8fa4b4' },
      },
      yAxis: {
        type: 'value',
        min: 0,
        max: 100,
        axisLabel: { color: '#8fa4b4' },
      },
      series: [{
        type: 'line',
        smooth: true,
        data: points.map((point) => point.value),
        areaStyle: {},
      }],
    })

    const resize = () => chart.resize()
    window.addEventListener('resize', resize)
    return () => {
      window.removeEventListener('resize', resize)
      chart.dispose()
    }
  }, [points])

  return <div ref={ref} className="chart" />
}
