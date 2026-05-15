import logging
from fastapi import APIRouter, Header, HTTPException, Body
from pydantic import BaseModel
import google.generativeai as genai

log = logging.getLogger(__name__)

router = APIRouter(tags=["AI"])

class AIGenerateRequest(BaseModel):
    title: str
    field: str
    current_content: str = ""

@router.post("/generate")
async def generate_ai_content(
    req: AIGenerateRequest
):
    try:
        # Using Gemini API key provided by user
        gemini_api_key = "AIzaSyBFH603cB19vzv2LMYvha970DDTm4ujem4"
        genai.configure(api_key=gemini_api_key)
        
        system_prompt = (
            "You are an elite offensive security expert writing a VAPT (Vulnerability Assessment and Penetration Testing) report. "
            "Write the specific requested section concisely, using professional technical language. "
            "Use Markdown formatting (like code blocks, bolding, lists) where appropriate. "
            "Do NOT include introductory phrases like 'Here is the description'. Just output the raw markdown content for the section. "
            "Keep the length appropriate for a typical vulnerability report section (1-3 paragraphs)."
        )
        
        prompts = {
            "description": f"Write the 'Description' section for a vulnerability titled '{req.title}'. Explain what the vulnerability is and how it occurs.",
            "impact": f"Write the 'Business Impact' section for a vulnerability titled '{req.title}'. Explain what an attacker could achieve.",
            "poc": f"Write a hypothetical 'Proof of Concept' section for '{req.title}'. Provide generic steps or a code snippet to reproduce it.",
            "recommendation": f"Write the 'Recommendation' section for a vulnerability titled '{req.title}'. Explain how a developer should fix this issue."
        }
        
        if req.field not in prompts:
            raise HTTPException(status_code=400, detail="Invalid field specified.")
            
        user_prompt = prompts[req.field]
        if req.current_content:
            user_prompt += f"\n\nThe user started writing this, use it as context if helpful:\n{req.current_content}"
            
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=system_prompt
        )
        
        response = model.generate_content(user_prompt)
        
        generated_text = response.text.strip()
        return {"content": generated_text}
        
    except Exception as e:
        log.error("AI Generation error: %s", str(e))
        raise HTTPException(status_code=500, detail=str(e))
