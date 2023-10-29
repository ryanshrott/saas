import streamlit as st
from mongo_auth import Authenticate
import os
from dotenv import load_dotenv
from utils import *
import webbrowser
import numpy as np
import pandas as pd
import openai

# Set Streamlit page configuration
st.set_page_config(page_title="SaaS", page_icon=":house", layout="centered", initial_sidebar_state="auto", menu_items=None)

# Load environment variables
load_dotenv()

# Display the main title
st.markdown('# Your SaaS App')

# Initialize the authenticator
st.session_state['authenticator'] = Authenticate("coolcookies267", "key3214", 60)

# Set default session state values if not already set
if 'authentication_status' not in st.session_state:
    st.session_state['authentication_status'] = None
if 'verified' not in st.session_state:
    st.session_state['verified'] = None

# Handle login if not authenticated and not verified
if not st.session_state['authentication_status'] and not st.session_state['verified']:
    st.session_state['authenticator'].login('Login', 'main')
if 'summarized_text' not in st.session_state:
    st.session_state['summarized_text'] = ''
if 'translation' not in st.session_state:
    st.session_state['translation'] = ''
# Handle actions for verified and authenticated users
if st.session_state['verified'] and st.session_state["authentication_status"]:
    st.session_state['authenticator'].logout('Logout', 'sidebar', key='123')

    openai.api_key = os.environ["OPENAI_API_KEY"]
    # Check if the user's email is subscribed
    st.session_state['subscribed'] = is_email_subscribed(st.session_state['email'])
    
    # Display subscription status
    if st.session_state.get('subscribed'):
        st.write('You are subscribed!')
    else:
        st.write('You are not subscribed!')

    # Free Tool
    st.write('This tool is free to use!')
    input1 = st.text_area('Enter your text to summarize here:')
    if st.button('Summarize') and input1 and input1 != '':
        response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-0613",
        messages=[
                {'role': 'system', 'content': f'You are a helpful assistant.'},
            {"role": "user", "content": f"Provide a summary of the following content: \n ```{input1}```"}
        ],
        temperature=0.0)
        st.session_state['summarized_text'] = response['choices'][0]['message']['content']
        
    st.write(st.session_state['summarized_text'])
    # Subscription-only Tool
    st.write('Subscription Only Tool')

    st.write('Special tool only subscribers can use!')
    input2 = st.text_area('Enter your text to translate here:')
    language = st.text_input('Enter the language you want to translate to:')
    if st.button('Translate') and input2 and language and input2 != '' and language != '':
        if not st.session_state.get('subscribed'):
            st.error('Please subscribe to use this tool!')
            webbrowser.open_new_tab(os.getenv('STRIPE_PAYMENT_URL'))
        else:
            response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo-0613",
            messages=[
                    {'role': 'system', 'content': f'You are a helpful assistant.'},
                {"role": "user", "content": f"Translate the text below to the language {language}: \n INPUT: ```{input2}```"}
            ],
            temperature=0.0)
            st.session_state['translation'] = response['choices'][0]['message']['content']
    
    st.write(st.session_state['translation'])

# Handle actions for users with correct password but unverified email
elif st.session_state["authentication_status"] == True:
    st.error('Your password was correct, but your email has not been not verified. Check your email for a verification link. After you verify your email, refresh this page to login.')
    
    # Add a button to resend the email verification
    if st.session_state.get('email'):
        if st.button(f"Resend Email Verification to {st.session_state['email']}"):
            resend_verification(st.session_state['email'])

# Handle actions for users with incorrect login credentials
elif st.session_state["authentication_status"] == False:
    st.error('Username/password is incorrect or does not exist. Reset login credential or register below.')
    forgot_password()
    register_new_user()

# Handle actions for new users or users with no authentication status
elif st.session_state["authentication_status"] == None:
    st.warning('New to SaaS app? Register below.')
    register_new_user()
