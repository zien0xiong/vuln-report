#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM客户端
用于与kimi2.5 API通信
"""

import json
import base64
from typing import Dict, Any, Optional, List
from pathlib import Path
import openai

from core.config import config


class LLMClient:
    """大模型客户端"""

    def __init__(self, api_key: str = None, base_url: str = None, model: str = None):
        """
        初始化LLM客户端

        Args:
            api_key: API密钥，默认从配置文件读取
            base_url: API基础URL，kimi2.5使用 OpenAI 兼容格式
            model: 模型名称
        """
        # 优先使用传入的参数，其次从配置文件读取
        llm_config = config.get_llm_config()

        self.api_key = api_key or llm_config.get("api_key", "")
        if not self.api_key:
            raise ValueError(
                "API key is required. "
                "请在 config.yaml 中配置 llm.api_key"
            )

        self.base_url = base_url or llm_config.get("base_url", "https://api.moonshot.cn/v1")
        self.model = model or llm_config.get("model", "kimi-k2.5")

        # 初始化OpenAI客户端（kimi2.5使用OpenAI兼容API）
        self.client = openai.OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )

    def chat(self,
             messages: List[Dict[str, str]],
             temperature: float = 1.0,
             max_tokens: int = 4000,
             response_format: Optional[Dict] = None) -> Dict[str, Any]:
        """
        发送聊天请求

        Args:
            messages: 消息列表，格式为 [{"role": "user", "content": "..."}]
            temperature: 温度参数 (kimi-k2.5 只接受 temperature=1)
            max_tokens: 最大token数
            response_format: 响应格式，如 {"type": "json_object"}

        Returns:
            包含响应内容的字典
        """
        try:
            kwargs = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }

            if response_format:
                kwargs["response_format"] = response_format

            response = self.client.chat.completions.create(**kwargs)

            return {
                "success": True,
                "content": response.choices[0].message.content,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "content": None
            }

    def complete(self,
                 prompt: str,
                 system_prompt: Optional[str] = None,
                 temperature: float = 1.0,
                 max_tokens: int = 4000,
                 json_mode: bool = False) -> Dict[str, Any]:
        """
        简单的单轮对话

        Args:
            prompt: 用户提示词
            system_prompt: 系统提示词
            temperature: 温度参数 (kimi-k2.5 只接受 temperature=1)
            max_tokens: 最大token数
            json_mode: 是否强制JSON输出

        Returns:
            包含响应内容的字典
        """
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})

        messages.append({"role": "user", "content": prompt})

        response_format = {"type": "json_object"} if json_mode else None

        return self.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format
        )

    def analyze(self, context: str, question: str,
                json_mode: bool = True) -> Dict[str, Any]:
        """
        分析型请求（用于Agent分析任务）

        Args:
            context: 上下文信息
            question: 具体问题
            json_mode: 是否返回JSON格式

        Returns:
            分析结果
        """
        system_prompt = """你是一个专业的安全分析助手，擅长分析漏洞报告和代码。
请基于提供的信息进行详细分析，并给出结构化的回答。"""

        prompt = f"""【上下文信息】
{context}

【问题】
{question}

请详细分析并给出回答。"""

        return self.complete(
            prompt=prompt,
            system_prompt=system_prompt,
            json_mode=json_mode
        )

    def vision_complete(
        self,
        image_path: str,
        prompt: str,
        model: Optional[str] = None,
        max_tokens: int = 1000,
    ) -> Dict[str, Any]:
        """
        多模态单轮对话（图片 + 文本）。

        Args:
            image_path: 本地图片路径
            prompt: 文本提示词
            model: 可选视觉模型名，默认读取 llm.vision_model 或 qwen-vl-max
            max_tokens: 最大输出 token
        """
        try:
            path = Path(image_path)
            if not path.exists():
                return {"success": False, "error": f"image not found: {image_path}", "content": None}

            suffix = path.suffix.lower()
            mime = {
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".png": "image/png",
                ".webp": "image/webp",
                ".bmp": "image/bmp",
            }.get(suffix, "image/png")
            b64 = base64.b64encode(path.read_bytes()).decode("ascii")
            data_url = f"data:{mime};base64,{b64}"

            vision_model = model or config.get("llm.vision_model", "qwen-vl-max")
            response = self.client.chat.completions.create(
                model=vision_model,
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": data_url}},
                        ],
                    }
                ],
                max_tokens=max_tokens,
            )
            return {
                "success": True,
                "content": response.choices[0].message.content,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                    "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                    "total_tokens": response.usage.total_tokens if response.usage else 0,
                },
            }
        except Exception as e:
            return {"success": False, "error": str(e), "content": None}

    def decide(self, situation: str, options: List[str],
               context: str = None) -> Dict[str, Any]:
        """
        决策型请求（用于Agent决策）

        Args:
            situation: 当前情况描述
            options: 可选的决策选项
            context: 额外上下文

        Returns:
            决策结果
        """
        system_prompt = """你是一个智能决策助手，需要在给定选项中做出最佳选择。
请分析情况，权衡利弊，给出决策和建议。"""

        prompt = f"""【当前情况】
{situation}

【可选方案】
"""
        for i, option in enumerate(options, 1):
            prompt += f"{i}. {option}\n"

        if context:
            prompt += f"\n【额外上下文】\n{context}"

        prompt += """

请给出你的决策：
{
  "decision": "选择的方案编号或名称",
  "confidence": 0.85,
  "reason": "决策理由",
  "action": "具体执行动作"
}"""

        return self.complete(
            prompt=prompt,
            system_prompt=system_prompt,
            json_mode=True
        )


class LLMToolUse:
    """LLM工具调用封装"""

    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client

    def extract_json(self, text: str) -> Optional[Dict]:
        """从文本中提取JSON"""
        try:
            # 尝试直接解析
            return json.loads(text)
        except json.JSONDecodeError:
            # 尝试提取代码块中的JSON
            import re
            json_pattern = r'```(?:json)?\s*(\{.*?\})\s*```'
            match = re.search(json_pattern, text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group(1))
                except:
                    pass

            # 尝试提取花括号中的内容
            try:
                start = text.find('{')
                end = text.rfind('}')
                if start != -1 and end != -1:
                    return json.loads(text[start:end+1])
            except:
                pass

        return None

    def safe_json_complete(self, prompt: str, max_retries: int = 3) -> Dict[str, Any]:
        """安全的JSON模式请求，带重试"""
        for attempt in range(max_retries):
            response = self.llm.complete(
                prompt=prompt,
                json_mode=True
            )

            if response["success"]:
                # 验证JSON是否可解析
                json_data = self.extract_json(response["content"])
                if json_data is not None:
                    return {
                        "success": True,
                        "data": json_data,
                        "raw": response["content"],
                        "usage": response.get("usage", {})
                    }

            # 重试
            if attempt < max_retries - 1:
                prompt = f"""之前的响应格式不正确，请确保返回有效的JSON格式。

{prompt}

注意：只返回JSON，不要包含其他文本。"""

        return {
            "success": False,
            "error": "Failed to get valid JSON response after retries",
            "raw": response.get("content") if response else None
        }
