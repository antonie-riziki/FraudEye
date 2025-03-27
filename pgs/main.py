import streamlit as st 
import sys
import google.generativeai as genai 
import time, random, socket, os

from st_social_media_links import SocialMediaIcons


sys.path.insert(1, './models')
print(sys.path.insert(1, '../models/'))


from func import send_sms, generate_otp, check_email, generate_captcha_text, generate_captcha_image, phishing_score, analyze_email_address, analyze_url, check_and_encrypt_password

from dotenv import load_dotenv

load_dotenv()


st.title("FRAUD-EYE")
st.image('./assets/1731707329357.png', width=900)

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(['🎯 Passwords', '🔗 Links', '🕵️ 2FA', '🔐 IP Control', '📧 Email usage', '📋 Report'])

with tab1:
	social_media_links = [
				'https://www.github.com/',
				'https://www.x.com',
				'https://www.facebook.com',
				'https:/www.whatsapp.com',
				'https://www.instagram.com'
				]

	password = st.text_input('Password:', type="password")
	confirm_password = st.text_input('Confirm Password:', type="password")
	encrypt_password_btn = st.button('Encrypt Password', use_container_width=True)

	if encrypt_password_btn:
		check_and_encrypt_password(password, confirm_password)

	social_icons = SocialMediaIcons(social_media_links)
	social_icons.render()

with tab2:
	links = st.text_input('Enter Suspicious link(s):')
	links_btn = st.button('Detect Phishing', use_container_width=True)
	if links_btn:
		analyze_url(links)

with tab3:
	two_factor = st.write('Two Factor Auth (2FA)')
	captcha_text = generate_captcha_text()
	get_captcha_image = generate_captcha_image(captcha_text)
	captcha_code = st.text_input('Captcha Code: ')
	submit_captcha_btn = st.button('Process', use_container_width=True)

	if submit_captcha_btn==True:
		if captcha_text == captcha_code:
			st.success('You can process to the system')
			st.toast('Captcha code Successfully Matched')
		else:
			st.error('Captcha code mismatch')

with tab4:
	ip_control = st.text_input('IP Address:')
	ip_control_btn = st.button('Device Details', use_container_width=True)
	ip_control_device_btn = st.button('Parental Control', use_container_width=True)
	if ip_control_device_btn:
		pass

with tab5:
	get_email = st.text_input("Enter Email")
	email_usage_btn = st.button("Check Email", use_container_width=True)
	if email_usage_btn:
		check_email(get_email)

with tab6:
	phone = st.number_input('Phone number:', value=None, min_value=0, max_value=int(10e10))
	report_btn = st.button('Report', use_container_width=True)
	if report_btn:
		pass