import React from 'react'

type Theme = 'dark' | 'light'

const ThemeToggle = () => {
    const [theme, setTheme] = React.useState<Theme>(() =>
        document.documentElement.classList.contains('light') ? 'light' : 'dark'
    )

    const toggleTheme = () => {
        const next: Theme = theme === 'dark' ? 'light' : 'dark'
        setTheme(next)
        document.documentElement.classList.toggle('light', next === 'light')
        localStorage.setItem('theme', next)
    }

    return (
        <button
            onClick={toggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className="p-2 rounded-md text-gray-300 hover:text-primary hover:bg-gray-700 transition-colors duration-200"
        >
            <i className={`fa-solid ${theme === 'dark' ? 'fa-sun' : 'fa-moon'} text-base`}></i>
        </button>
    )
}

export default ThemeToggle
