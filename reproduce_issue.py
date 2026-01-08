from src.analyzers.static_analyzer import StaticAnalyzer
import asyncio

async def test():
    analyzer = StaticAnalyzer()
    code = 'password = "admin123"\neval(input())'
    
    bandit_result = await analyzer.run_bandit(code, 'test.py')
    print(f'Bandit: {len(bandit_result)} findings')  # Should be >= 2
    
    ruff_result = await analyzer.run_ruff(code, 'test.py')
    print(f'Ruff: {len(ruff_result)} findings')

if __name__ == "__main__":
    asyncio.run(test())
