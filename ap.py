import os
import requests
import base64
import streamlit as st
import google.generativeai as genai
import shodan

# --- PAGE CONFIG ---
st.set_page_config(
    page_title="Ai NetRunner CyberTool",
    page_icon="🤖",
    layout="centered"
)

# --- GLOBAL INITIALIZATION ---
try:
    genai.configure(api_key=st.secrets["GOOGLE_API_KEY"])
    shodan_client = shodan.Shodan(st.secrets["SHODAN_API_KEY"])
    virus_total_api_key = st.secrets["VIRUS_TOTAL_API_KEY"]
except (KeyError, Exception) as e:
    st.error(f"🔴 FATAL ERROR: Could not load API keys from st.secrets. Details: {e}")
    st.stop()

# --- TOOL DEFINITIONS WITH IMPROVED DOCSTRINGS ---

def shodan_ip_tool(ip_address: str) -> str:
    """
    Provides a security summary for a given IPv4 address from Shodan. Use this for IP addresses ONLY.
    Args:
        ip_address (str): The IP address to query, for example "8.8.8.8".
    """
    st.info(f"Tool running: `shodan_ip_tool` with IP: {ip_address}")
    try:
        host_info = shodan_client.host(ip_address)
        summary = (
            f"**IP:** {host_info.get('ip_str')}\n\n"
            f"**Organization:** {host_info.get('org', 'N/A')}\n\n"
            f"**ISP:** {host_info.get('isp', 'N/A')}\n\n"
            f"**ASN:** {host_info.get('asn', 'N/A')}\n\n"
            f"**Hostnames:** {', '.join(host_info.get('hostnames', [])) or 'N/A'}\n\n"
            f"**Country:** {host_info.get('country_name', 'N/A')}\n\n"
            "**Open Ports:**\n"
        )
        if not host_info.get('data'):
            summary += "- No open ports found."
        else:
            for item in host_info.get('data', []):
                summary += f"- Port: {item['port']}\n"
        return summary
    except shodan.APIError as e:
        return f"Error from Shodan API: {e}"

def virus_total_url_tool(url_to_scan: str) -> str:
    """
    Analyzes a full URL, including 'https://' or 'http://'. Use this tool to check the reputation of a specific page, link, or path.
    Args:
        url_to_scan (str): The full URL to analyze, for example "https://www.some-malicious-site.com/bad-page.html".
    """
    st.info(f"Tool running: `virus_total_url_tool` with URL: {url_to_scan}")
    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": virus_total_api_key}
    response = requests.get(url, headers=headers)
    return response.text

def virus_total_domain_tool(domain_to_scan: str) -> str:
    """
    Provides reputation, WHOIS, and DNS data for a base domain name. Use this for domains like 'google.com' or 'shaktatech.com'. Do not use this for full URLs that include paths or 'https://'.
    Args:
        domain_to_scan (str): The domain name to analyze, for example "google.com".
    """
    st.info(f"Tool running: `virus_total_domain_tool` with domain: {domain_to_scan}")
    cleaned_domain = domain_to_scan.strip()
    url = f"https://www.virustotal.com/api/v3/domains/{cleaned_domain}"
    headers = {"accept": "application/json", "x-apikey": virus_total_api_key}
    response = requests.get(url, headers=headers)
    return response.text

def virus_total_hash_tool(hash_to_scan: str) -> str:
    """
    Analyzes a file hash (MD5, SHA1, or SHA256) using VirusTotal for malware signatures.
    Args:
        hash_to_scan (str): The file hash to analyze.
    """
    st.info(f"Tool running: `virus_total_hash_tool` with hash: {hash_to_scan}")
    cleaned_hash = hash_to_scan.strip()
    url = f"https://www.virustotal.com/api/v3/files/{cleaned_hash}"
    headers = {"accept": "application/json", "x-apikey": virus_total_api_key}
    response = requests.get(url, headers=headers)
    return response.text

# --- MAIN APP LOGIC ---
if __name__ == '__main__':
    st.title('🤖 Ai NetRunner CyberTool')
    st.markdown("This app uses Gemini 1.5 Pro with tool-calling to analyze cybersecurity indicators.")
    st.image("https://www.wallpaperflare.com/static/66/41/250/cyberpunk-futuristic-computer-interfaces-wallpaper.jpg")

    # Create the model with the new system instruction
    model = genai.GenerativeModel(
        model_name='gemini-2.5-pro',
        tools=[shodan_ip_tool, virus_total_url_tool, virus_total_domain_tool, virus_total_hash_tool],
        system_instruction="You are an expert cybersecurity analyst. When the user provides an indicator (like an IP, domain, or URL), your primary goal is to use the most appropriate tool to analyze it directly without asking for confirmation. Be decisive and choose the single best tool for the job based on the indicator's format."
    )

    chat = model.start_chat(enable_automatic_function_calling=True)

    user_message = st.text_area('Insert your query:', placeholder="e.g., scan the ip 8.8.8.8, or analyze the domain google.com")
        
    if st.button("Analyze", type="primary"):
        if user_message.strip():  
            with st.spinner("Gemini is thinking and may be using tools..."):
                try:
                    response = chat.send_message(user_message)
                    st.success("Analysis Complete!")
                    st.markdown(response.text)
                except Exception as e:
                    st.error(f"An error occurred during content generation: {e}")
        else:
            st.warning("Please enter a query before analyzing!")