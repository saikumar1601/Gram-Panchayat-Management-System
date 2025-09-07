# myapp/urls.py
from django.urls import path
from . import views
from .views import (
    advanced_query_begin,
    advanced_query_step1,
    advanced_query_step2,
    advanced_query_execute,
)


urlpatterns = [
    path('', views.login_before, name='login_before'),
    path('base/', views.base, name='base'),
    path('login/', views.login_view, name='login'),
    path('home/', views.home_view, name='home'),
    path('login_register/', views.login_register_view, name='login_register'),
    path('register/', views.register_view, name='register'),
    path('view_notices/', views.view_notices, name='view_notices'),
    path('add_notice/', views.add_notice, name='add_notice'),
    path('citizen_home/', views.citizen_home, name='citizen_home'),
    path('update_user_roles/', views.update_user_roles, name='update_user_roles'),
    path('admin_home/', views.admin_home, name='admin_home'),
    path('government_monitors/', views.government_monitors, name='government_monitors'),
    path('logout/', views.logout, name='logout'),
    path('dashboard/',views.dashboard, name='dashboard'),
    path('update_profile/', views.update_profile, name='update_profile'),
    path("add-complaint/", views.add_complaint, name="add_complaint"),
    path("remove-complaint/", views.remove_complaint, name="remove_complaint"),
    path('citizen_admin/',views.citizen_admin,name='citizen_admin'),
    path('village_info/<int:user_id>/', views.view_village_info, name='view_village_info'),
    path('employee_home/', views.employee_home, name='employee_home'),
    path('employee_query/', views.employee_query, name='employee_query'),  # New URL pattern
    path("advanced_query_begin/", views.advanced_query_begin, name="advanced_query_begin"),
    path("advanced_query_step1/", views.advanced_query_step1, name="advanced_query_step1"),
    path("advanced_query_step2/", views.advanced_query_step2, name="advanced_query_step2"),
    path("advanced_query_execute/", views.advanced_query_execute, name="advanced_query_execute"),
    path('monitor_admin/',views.monitor_admin,name='monitor_admin'),
    path('employee_admin/',views.employee_admin,name='employee_admin'),
    path('scheme_admin/',views.scheme_admin,name='scheme_admin'),
    path('scheme_enrollment_admin/',views.scheme_enrollment_admin,name='scheme_enrollment_admin'),
    path('complaint_admin/',views.complaint_admin,name='complaint_admin'),
    path('certificate_admin/', views.certificate_admin, name='certificate_admin'),
    path('tax_record_admin/', views.tax_record_admin, name='tax_record_admin'),
    path('property_admin/', views.property_admin, name='property_admin'),
    path('notice_admin/', views.notice_admin, name='notice_admin'),
    path('health_record_admin/', views.health_record_admin, name='health_record_admin'),
    path('education_record_admin/', views.education_record_admin, name='education_record_admin'),
    path('agriculture_record_admin/', views.agriculture_record_admin, name='agriculture_record_admin'),
    path('village_admin/',views.village_admin,name='village_admin'),
    path('employee_insert/',views.employee_insert,name='employee_insert'),
    path('delete_account/',views.delete_account,name='delete_account'),
    path('ge-update/<int:user_id>/', views.ge_update, name='ge_update'),
    path('pe-update/<int:user_id>/', views.pe_update, name='pe_update'),
    path('government_monitor_query/',views.government_monitor_query,name='government_monitor_query'),
    path('employee_modify/',views.employee_modify,name = 'employee_modify'),
    path('employee_delete/',views.employee_delete,name = 'employee_delete'),
]



# Add this to your project's urls.py
# from django.urls import path, include
# 
# urlpatterns = [
#     path('admin/', admin.site.urls),
#     path('', include('myapp.urls')),
# ]