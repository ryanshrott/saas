import streamlit as st
import yaml
from pymongo import MongoClient
from dotenv import load_dotenv
from mongo_auth import Authenticate
import os
import stripe
load_dotenv(".env")

st.title('Account Settings')
stripe.api_key = os.getenv("STRIPE_API_KEY")

def update_user_details():
    if authentication_status:
        try:
            if st.session_state['authenticator'].update_user_details(username, 'Update user details'):
                st.success('Entries updated successfully')
        except Exception as e:
            st.error(e)
def reset_password():
    if authentication_status:
        try:
            if st.session_state['authenticator'].reset_password(username, 'Reset password'):
                st.success('Password modified successfully')
        except Exception as e:
            st.error(e)   

name, authentication_status, username = st.session_state['authenticator'].login('Login', 'main')

# Define function to cancel subscriptions based on email
def cancel_subscriptions(email):
    try:
        # List customers by email
        customers = stripe.Customer.list(email=email, limit=100)

        # If no customers found, return a message
        if len(customers.data) == 0:
            return "No customer found with this email."

        # Iterate over customers (though typically there should only be one)
        for customer in customers.data:
            # List all subscriptions for the customer ID
            subscriptions = stripe.Subscription.list(customer=customer.id, limit=100)

            # Cancel all subscriptions for the customer ID
            for subscription in subscriptions:
                stripe.Subscription.delete(subscription.id)
        
        return f"All subscriptions for {email} have been canceled."
    except Exception as e:
        return str(e)


if st.session_state["authentication_status"]:
    update_user_details()
    reset_password()
    if st.session_state['verified'] and st.session_state["authentication_status"]:
        st.session_state['authenticator'].logout('Logout', 'sidebar', key='123')
    if st.session_state.get('subscribed'):
        with st.expander('Manage subscription'):
            if st.button('Cancel subscription'):
                response = cancel_subscriptions(st.session_state.get('email'))
                st.success(response)


else:
    st.write('You are not logged in')
