import requests
import time

BASE_URL = "http://127.0.0.1:5000"
LOGIN_URL = f"{BASE_URL}/login"

def simulate_brute_force(num_attempts=20):
    print(f"[*] بدء محاكاة {num_attempts} محاولة تسجيل دخول فاشلة...")
    
    test_username = "test_user_bf"
    incorrect_password = "wrong_password_123" 
    
    for i in range(1, num_attempts + 1):
        data = {
            "username": test_username,
            "password": incorrect_password
        }
        
        try:
            response = requests.post(LOGIN_URL, json=data)
            
            try:
                response_data = response.json()
                risk = response_data.get("risk", "N/A")
                message = response_data.get("message", "No message")
            except:
                risk = "BLOCKED (No JSON Response)"
                message = response.text.split('\n')[0].strip()
            
            status = "PASS" if response.status_code == 401 or response.status_code == 403 else "FAIL"
            
            print(f"[{i:02d}/{num_attempts}] Status: {status} | Code: {response.status_code} | Risk: {risk} | Message: {message}")
            
            if risk.startswith("High") or "BLOCKED" in risk:
                 print("\n[!!!] تم رصد تفعيل قاعدة الحظر الآلي (High/Blocked).")
                 
            time.sleep(0.2) 
            
        except requests.exceptions.ConnectionError:
            print(f"\n[CRITICAL] فشل الاتصال بالخادم على {BASE_URL}. تأكد من تشغيل تطبيق Flask.")
            break
        except Exception as e:
            print(f"[ERROR] حدث خطأ غير متوقع: {e}")
            break

    print("\n[*] انتهت المحاكاة.")

if __name__ == "__main__":
    simulate_brute_force()