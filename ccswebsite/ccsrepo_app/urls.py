from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='home'),
    path('register/', views.StudentRegister, name='register'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    #Manuscript
    path('manuscript-page/', views.upload_manuscript, name='manuscript_upload_page'),
    path('finalize/<int:manuscript_id>/<str:extracted_abstract>/', views.final_manuscript_page, name='final_manuscript_page'),
    path('manuscript-search/', views.manuscript_search_page, name='manuscript_search_page'),
    #User to verify
    path('adviser-request/', views.request_adviser_view, name='adviser_request'),
    path('adviser-request-success/', views.success_request_view, name='adviser_request_success'),
    #adviser
    path('adviser-approve-student/', views.approve_student_view, name='adviser_approve_student'),
    path('adviser-manuscripts/', views.adviser_manuscript, name='adviser_manuscript'),
    path('adviser-review/<int:manuscript_id>/', views.adviser_review, name='adviser_review'),
    #admin
    path('manage-users/', views.ManageAdviser, name='manage_users'),
    path('manage-program/', views.manage_program, name='manage_program'),
    path('manage-category/', views.manage_category, name='manage_category'),
    path('manage-batch/', views.manage_batch, name='manage_batch'),
    path('manage-type/', views.manage_type, name='manage_type'),
    #Student
    path('my-manuscripts/', views.student_manuscripts_view, name='student_manuscripts'),
    #Redirecting
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
]