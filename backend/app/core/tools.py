"""
SecureAI Toolkit - 安全工具集成层
集成 pwntools、requests、z3-solver 等安全工具
提供统一的工具调用接口给 Agent 使用
"""
import logging
import re
import subprocess
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SecurityToolRegistry:
    """安全工具注册表"""

    def __init__(self):
        self._tools: dict[str, dict[str, Any]] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        """注册默认安全工具集"""
        self.register_tool({
            "name": "http_request",
            "description": "发送 HTTP 请求，支持 GET/POST/PUT/DELETE 方法，可自定义 headers 和 body",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE"], "default": "GET"},
                    "headers": {"type": "object", "description": "请求头"},
                    "body": {"type": "string", "description": "请求体"},
                    "params": {"type": "object", "description": "查询参数"},
                },
                "required": ["url"],
            },
            "handler": self._http_request,
        })

        self.register_tool({
            "name": "z3_solve",
            "description": "使用 Z3 SMT 求解器解决约束求解问题，常用于密码学和逆向工程",
            "parameters": {
                "type": "object",
                "properties": {
                    "constraints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "约束表达式列表（Python z3 语法）",
                    },
                    "variables": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "变量声明列表（如 'x = BitVec(\"x\", 32)'）",
                    },
                },
                "required": ["constraints", "variables"],
            },
            "handler": self._z3_solve,
        })

        self.register_tool({
            "name": "run_command",
            "description": "执行系统命令（沙箱环境），用于运行安全工具如 nmap、sqlmap 等",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的命令"},
                    "timeout": {"type": "integer", "default": 30, "description": "超时秒数"},
                },
                "required": ["command"],
            },
            "handler": self._run_command,
        })

        self.register_tool({
            "name": "decode_base64",
            "description": "Base64 解码",
            "parameters": {
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Base64 编码的数据"},
                },
                "required": ["data"],
            },
            "handler": self._decode_base64,
        })

        self.register_tool({
            "name": "encode_base64",
            "description": "Base64 编码",
            "parameters": {
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "要编码的数据"},
                },
                "required": ["data"],
            },
            "handler": self._encode_base64,
        })

        self.register_tool({
            "name": "xor_decrypt",
            "description": "XOR 异或解密/加密",
            "parameters": {
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "数据（十六进制）"},
                    "key": {"type": "string", "description": "密钥（十六进制）"},
                },
                "required": ["data", "key"],
            },
            "handler": self._xor_decrypt,
        })

        self.register_tool({
            "name": "pwn_connect",
            "description": "使用 pwntools 连接远程服务（TCP）",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "目标主机"},
                    "port": {"type": "integer", "description": "目标端口"},
                    "payload": {"type": "string", "description": "发送的 payload（十六进制）"},
                },
                "required": ["host", "port"],
            },
            "handler": self._pwn_connect,
        })

        self.register_tool({
            "name": "regex_extract",
            "description": "使用正则表达式从文本中提取信息（如 flag 格式匹配）",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "输入文本"},
                    "pattern": {"type": "string", "description": "正则表达式"},
                },
                "required": ["text", "pattern"],
            },
            "handler": self._regex_extract,
        })

    def register_tool(self, tool: dict[str, Any]):
        """注册工具"""
        self._tools[tool["name"]] = tool
        logger.info(f"Registered tool: {tool['name']}")

    def get_tool(self, name: str) -> Optional[dict[str, Any]]:
        """获取工具"""
        return self._tools.get(name)

    def list_tools(self) -> list[dict[str, Any]]:
        """列出所有工具（不含 handler）"""
        return [
            {k: v for k, v in tool.items() if k != "handler"}
            for tool in self._tools.values()
        ]

    def get_openai_tools_schema(self) -> list[dict[str, Any]]:
        """生成 OpenAI function calling 格式的工具定义"""
        return [
            {
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool["description"],
                    "parameters": tool["parameters"],
                },
            }
            for tool in self._tools.values()
        ]

    async def execute_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """执行工具"""
        tool = self._tools.get(name)
        if not tool:
            return f"Error: Tool '{name}' not found"
        try:
            result = await tool["handler"](**arguments)
            return str(result)
        except Exception as e:
            logger.error(f"Tool execution error [{name}]: {e}")
            return f"Error executing tool '{name}': {e}"

    # ===== 工具实现 =====

    async def _http_request(self, url: str, method: str = "GET",
                            headers: Optional[dict] = None,
                            body: Optional[str] = None,
                            params: Optional[dict] = None) -> str:
        import httpx
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
                params=params,
            )
            return (
                f"Status: {response.status_code}\n"
                f"Headers: {dict(response.headers)}\n"
                f"Body: {response.text[:5000]}"
            )

    async def _z3_solve(self, constraints: list[str], variables: list[str]) -> str:
        try:
            from z3 import Solver, sat
            solver = Solver()
            local_vars = {}
            exec("\n".join(variables), {}, local_vars)
            for constraint in constraints:
                exec(f"solver.add({constraint})", {**local_vars, "solver": solver})
            if solver.check() == sat:
                model = solver.model()
                result = {str(v): str(model.eval(local_vars[v]) if v in local_vars else model[v])
                          for v in model.decls()}
                return f"Solution found: {result}"
            return "No solution found (UNSAT)"
        except ImportError:
            return "Error: z3-solver not installed. Run: pip install z3-solver"
        except Exception as e:
            return f"Z3 solve error: {e}"

    async def _run_command(self, command: str, timeout: int = 30) -> str:
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout
            if result.stderr:
                output += f"\nSTDERR:\n{result.stderr}"
            if result.returncode != 0:
                output += f"\nReturn code: {result.returncode}"
            return output[:10000]
        except subprocess.TimeoutExpired:
            return f"Command timed out after {timeout}s"
        except Exception as e:
            return f"Command error: {e}"

    async def _decode_base64(self, data: str) -> str:
        import base64
        try:
            decoded = base64.b64decode(data).decode("utf-8", errors="replace")
            return decoded
        except Exception as e:
            return f"Base64 decode error: {e}"

    async def _encode_base64(self, data: str) -> str:
        import base64
        return base64.b64encode(data.encode()).decode()

    async def _xor_decrypt(self, data: str, key: str) -> str:
        data_bytes = bytes.fromhex(data)
        key_bytes = bytes.fromhex(key)
        result = bytes(
            data_bytes[i] ^ key_bytes[i % len(key_bytes)]
            for i in range(len(data_bytes))
        )
        try:
            return result.decode("utf-8")
        except UnicodeDecodeError:
            return result.hex()

    async def _pwn_connect(self, host: str, port: int,
                           payload: Optional[str] = None) -> str:
        try:
            from pwn import remote
            r = remote(host, port, level="error")
            if payload:
                r.send(bytes.fromhex(payload))
            try:
                response = r.recvrepeat(timeout=3)
                r.close()
                return f"Response: {response.decode('utf-8', errors='replace')}"
            except Exception:
                r.close()
                return "Connection established, no immediate response"
        except ImportError:
            return "Error: pwntools not installed. Run: pip install pwntools"
        except Exception as e:
            return f"Pwn connect error: {e}"

    async def _regex_extract(self, text: str, pattern: str) -> str:
        try:
            matches = re.findall(pattern, text)
            if matches:
                return f"Matches found: {matches}"
            return "No matches found"
        except re.error as e:
            return f"Regex error: {e}"


# 全局单例
tool_registry = SecurityToolRegistry()
