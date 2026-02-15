import { useState } from "react"
import "./App.css"

function App() {
  const [count, setCount] = useState(0)

  const increase = () => {
    setCount(prev => prev + 1)
  }

  const decrease = () => {
    if (count > 0) {
      setCount(prev => prev - 1)
    }
  }

  const reset = () => {
    setCount(0)
  }

  return (
    <div className="container">
      <h1>MindStep React Counter 🔥</h1>

      <h2>Count: {count}</h2>

      <div className="buttons">
        <button onClick={increase}>Increase</button>
        <button onClick={decrease}>Decrease</button>
        <button onClick={reset}>Reset</button>
      </div>
    </div>
  )
}

export default App
