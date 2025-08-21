import streamlit as st
import math
import pandas as pd
import plotly.express as px

# Page Configuration
st.set_page_config(
    page_title="Health Risk Analytics Suite",
    layout="wide",
    page_icon=" "
)

# Custom CSS
st.markdown("""
<style>
    .main {background-color: #f5f5f5; color: white;}
    h1, h2, h3, h4, h5, h6 {color: #d32f2f;}
    /* Target st.subheader */
    .stMarkdown h3 {
        color: white !important;
    }

    /* Target st.caption */
    .stCaption {
        color: white !important;
    .sidebar .sidebar-content {background-color: #ffffff; color: black;}
    [data-testid="stForm"] {background-color: #fffg30; padding: 20px; border-radius: 10px; color: black;}
    .risk-low {color: #4CAF50 !important; font-weight: bold !important;}
    .risk-moderate {color: #FFC107 !important; font-weight: bold !important;}
    .risk-high {color: #D32F2F !important; font-weight: bold !important;}
</style>
""", unsafe_allow_html=True)

# Diabetes Risk Analytics
def diabetes_risk_analytics():
    with st.form("diabetes_form"):
        st.subheader("Diabetes Risk Assessment")
        st.caption("Based on ADA guidelines and FINDRISC score")

        age = st.number_input("Age (years)", min_value=18, max_value=120, step=1)
        weight = st.number_input("Weight (kg)", min_value=30.0, max_value=300.0, step=0.1)
        height = st.number_input("Height (m)", min_value=1.0, max_value=2.5, step=0.01)
        waist = st.number_input("Waist Circumference (cm)", min_value=50, max_value=200)
        activity = st.number_input("Physical Activity (days/week)", min_value=0, max_value=7)
        family = st.selectbox("Family History of Diabetes", ["No", "Yes"])
        glucose = st.number_input("Fasting Blood Glucose (mg/dL)", min_value=50, max_value=300)
        hba1c = st.number_input("HbA1c (%)", min_value=3.0, max_value=15.0, step=0.1)

        if st.form_submit_button("Assess Risk"):
            bmi = weight / (height ** 2)
            score = 0
            if 45 <= age <= 54:
                score += 2
            elif age > 54:
                score += 3
            if 25 <= bmi <= 30:
                score += 1
            elif bmi > 30:
                score += 3
            if waist >= 94:
                score += 3
            if activity < 4:
                score += 2
            if family == "Yes":
                score += 3
            if 100 <= glucose <= 125:
                score += 5
            elif glucose >= 126:
                score += 10
            if score < 7:
                risk = "Low Risk"
                cls = "risk-low"
            elif 7 <= score <= 14:
                risk = "Moderate Risk"
                cls = "risk-moderate"
            else:
                risk = "High Risk"
                cls = "risk-high"
            st.markdown(f"**Risk Score:** {score} points")
            st.markdown(f"**Risk Classification:** <span class='{cls}'>{risk}</span>", unsafe_allow_html=True)
            st.caption("Interpretation: Low (<7), Moderate (7-14), High (>14)")

# Heart Disease Risk Analytics
def heart_disease_risk_analytics():
    with st.form("heart_form"):
        st.subheader("Cardiovascular Risk Assessment")
        st.caption("Based on ASCVD 10-Year Risk Formula")

        age = st.number_input("Age (years)", min_value=18, max_value=120)
        gender = st.selectbox("Gender", ["Male", "Female"])
        chol = st.number_input("Total Cholesterol (mg/dL)", min_value=100, max_value=400)
        hdl = st.number_input("HDL Cholesterol (mg/dL)", min_value=20, max_value=100)
        sbp = st.number_input("Systolic BP (mmHg)", min_value=90, max_value=200)
        smoke = st.selectbox("Smoker", ["No", "Yes"])
        diabetes = st.selectbox("Diabetes", ["No", "Yes"])

        if st.form_submit_button("Assess Risk"):
            x = (age * 0.08) + (chol * 0.003) - (hdl * 0.004) + (sbp * 0.01)
            x += 0.5 if smoke == "Yes" else 0
            x += 0.4 if diabetes == "Yes" else 0
            risk_pct = (1 - (0.88936 ** x)) * 100
            if risk_pct < 5:
                risk = "Low Risk"
                cls = "risk-low"
            elif 5 <= risk_pct <= 7.5:
                risk = "Moderate Risk"
                cls = "risk-moderate"
            else:
                risk = "High Risk"
                cls = "risk-high"
            st.markdown(f"**10-Year Risk:** {risk_pct:.1f}%")
            st.markdown(f"**Classification:** <span class='{cls}'>{risk}</span>", unsafe_allow_html=True)
            st.caption("Interpretation: Low (<5%), Moderate (5-7.5%), High (>7.5%)")

# Cancer Risk Analytics
def cancer_risk_analytics():
    with st.form("cancer_form"):
        st.subheader("Oncology Risk Assessment")
        st.caption("Based on WHO/IARC simplified model")

        age = st.number_input("Age", min_value=18, max_value=120)
        gender = st.selectbox("Gender", ["Male", "Female"])
        family = st.selectbox("Family History of Cancer", ["No", "Yes"])
        packs = st.number_input("Smoking (pack-years)", min_value=0, max_value=100)
        alcohol = st.number_input("Alcohol (drinks/week)", min_value=0, max_value=50)
        bmi = st.number_input("BMI", min_value=15.0, max_value=50.0)
        activity = st.number_input("Physical Activity (days/week)", min_value=0, max_value=7)

        if st.form_submit_button("Assess Risk"):
            score = 0
            if age > 50:
                score += 2
            if family == "Yes":
                score += 2
            if packs > 20:
                score += 3
            if (gender == "Male" and alcohol > 7) or (gender == "Female" and alcohol > 14):
                score += 1
            if bmi > 30:
                score += 1
            if activity < 3:
                score += 1
            if score <= 2:
                risk = "Low Risk"
                cls = "risk-low"
            elif 3 <= score <= 5:
                risk = "Moderate Risk"
                cls = "risk-moderate"
            else:
                risk = "High Risk"
                cls = "risk-high"
            st.markdown(f"**Risk Score:** {score} points")
            st.markdown(f"**Classification:** <span class='{cls}'>{risk}</span>", unsafe_allow_html=True)
            st.caption("Interpretation: Low (0-2), Moderate (3-5), High (>5)")

# Eye Risk Analytics
def eye_risk_analytics():
    with st.form("eye_form"):
        st.subheader("Ocular Risk Assessment")
        st.caption("Diabetic Retinopathy/Glaucoma Risk Model")

        diabetes = st.selectbox("Diabetes Diagnosis", ["No", "Yes"])
        hba1c = st.number_input("HbA1c (%)", min_value=3.0, max_value=15.0) if diabetes == "Yes" else 0
        years = st.number_input("Years with Diabetes", min_value=0, max_value=50) if diabetes == "Yes" else 0
        pressure = st.number_input("Intraocular Pressure (mmHg)", min_value=5, max_value=40)
        family = st.selectbox("Family History of Glaucoma", ["No", "Yes"])
        hypertension = st.selectbox("Hypertension", ["No", "Yes"])

        if st.form_submit_button("Assess Risk"):
            score = 0
            if diabetes == "Yes":
                if hba1c > 7:
                    score += 2
                if years > 10:
                    score += 2
            if hypertension == "Yes":
                score += 1
            if family == "Yes":
                score += 1
            if pressure > 21:
                score += 2
            if score <= 2:
                risk = "Low Risk"
                cls = "risk-low"
            elif 3 <= score <= 4:
                risk = "Moderate Risk"
                cls = "risk-moderate"
            else:
                risk = "High Risk"
                cls = "risk-high"
            st.markdown(f"**Risk Score:** {score} points")
            st.markdown(f"**Classification:** <span class='{cls}'>{risk}</span>", unsafe_allow_html=True)
            st.caption("Interpretation: Low (0-2), Moderate (3-4), High (>4)")
def public_health_tracker():
    st.title("Indian Public Health Tracker")

    st.header("COVID-19 Outbreak Map")
    health_df = pd.DataFrame({
        'city': ['Mumbai', 'Delhi', 'Bengaluru', 'Chennai', 'Kolkata'],
        'lat': [19.0760, 28.7041, 12.9716, 13.0827, 22.5726],
        'lon': [72.8777, 77.1025, 77.5946, 80.2707, 88.3639],
        'covid_cases': [10000, 12000, 9000, 7000, 8000],
        'covid_deaths': [300, 400, 250, 200, 220],
        'covid_recoveries': [9500, 11500, 8700, 6800, 7700]
    })

    fig = px.scatter_mapbox(
        health_df, lat='lat', lon='lon',
        size='covid_cases', color='covid_cases',
        hover_name='city', hover_data=['covid_deaths', 'covid_recoveries'],
        color_continuous_scale='reds',
        mapbox_style="carto-positron",
        zoom=4,
        center={"lat": 22.9734, "lon": 78.6569}  # Center of India
    )
    fig.update_layout(margin={"r": 0, "t": 0, "l": 0, "b": 0}, height=600)
    st.plotly_chart(fig)

    st.header("Health Issues Trend (2013-2022)")
    years = list(range(2013, 2023))
    issues = ['Diabetes', 'Heart Disease', 'Cancer', 'Tuberculosis', 'Malaria', 'Dengue', 'Hypertension']
    data = {
        'Year': [],
        'Health Issue': [],
        'Cases (thousands)': []
    }

    import random
    for issue in issues:
        base = random.randint(100, 300)
        for year in years:
            fluctuation = random.randint(-10, 10)
            base += fluctuation
            data['Year'].append(year)
            data['Health Issue'].append(issue)
            data['Cases (thousands)'].append(base)

    trend_df = pd.DataFrame(data)
    fig = px.line(trend_df, x='Year', y='Cases (thousands)', color='Health Issue',
                  color_discrete_sequence=px.colors.qualitative.Set2)
    fig.update_layout(
        plot_bgcolor='white',
        xaxis_title='Year',
        yaxis_title='Cases (in thousands)',
        height=500
    )
    st.plotly_chart(fig)

    st.subheader("COVID-19 Statistics by City")
    st.dataframe(health_df.style.background_gradient(cmap='Reds'), use_container_width=True)
# Dummy data for public health
health_df = pd.DataFrame({
    'city': ['Delhi', 'Mumbai', 'Chennai', 'Kolkata'],
    'lat': [28.61, 19.07, 13.08, 22.57],
    'lon': [77.23, 72.88, 80.27, 88.36],
    'covid_cases': [350000, 420000, 210000, 180000],
    'covid_deaths': [8000, 9000, 3000, 2000],
    'covid_recoveries': [340000, 410000, 200000, 175000]
})

trend_df = pd.DataFrame({
    'Year': list(range(2013, 2023)) * 2,
    'Health Issue': ['Diabetes']*10 + ['Hypertension']*10,
    'Cases (thousands)': [30, 35, 40, 50, 55, 60, 65, 70, 80, 90] + [40, 45, 50, 55, 60, 70, 75, 85, 95, 100]
})

# Main App
st.title("Comprehensive Health Risk Analytics Suite")
st.write("""
### Clinical Decision Support System
Assess health risks using evidence-based models from leading medical organizations
""")

# Sidebar Navigation
analytics_tool = st.sidebar.radio(
    "Select Health Analytics",
    ["Diabetes Risk", "Cardiovascular Risk", "Oncology Risk", "Ocular Risk", "Public Health Tracker"],
    help="Choose a health risk assessment tool"
)

# Show selected analytics
if analytics_tool == "Diabetes Risk":
    diabetes_risk_analytics()
elif analytics_tool == "Cardiovascular Risk":
    heart_disease_risk_analytics()
elif analytics_tool == "Oncology Risk":
    cancer_risk_analytics()
elif analytics_tool == "Ocular Risk":
    eye_risk_analytics()
elif analytics_tool == "Public Health Tracker":
    st.title(" Indian Public Health Tracker")

    st.header("COVID-19 Outbreak Map")
    fig = px.scatter_mapbox(health_df, lat='lat', lon='lon',
                            size='covid_cases', color='covid_cases',
                            hover_name='city', hover_data=['covid_deaths', 'covid_recoveries'],
                            color_continuous_scale='reds',
                            mapbox_style="carto-positron",
                            zoom=4)
    fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0}, height=600)
    st.plotly_chart(fig)

    st.header("Health Issues Trend (2013-2022)")
    fig = px.line(trend_df, x='Year', y='Cases (thousands)', color='Health Issue',
                  color_discrete_sequence=px.colors.qualitative.Plotly)
    fig.update_layout(plot_bgcolor='white', xaxis_title='Year', yaxis_title='Cases (in thousands)', height=500)
    st.plotly_chart(fig)

    st.subheader("COVID-19 Statistics by City")
    st.dataframe(health_df.style.background_gradient(cmap='Reds'), use_container_width=True)

# Methodology Section
st.sidebar.markdown("---")
st.sidebar.write("""
**Methodology Sources:**
- American Diabetes Association (ADA)
- Framingham Heart Study
- World Health Organization (WHO)
- International Agency for Research on Cancer (IARC)
- National Eye Institute guidelines
""")
