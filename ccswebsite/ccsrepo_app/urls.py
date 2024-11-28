from django.urls import path
from . import views

urlpatterns = [
    path('', views.index_view, name='home'),
    path('register/', views.StudentRegister, name='register'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    #Faculty
    path('my-faculty-manuscripts/', views.faculty_manuscripts_view, name='faculty_manuscripts'),
    path('manuscripts-faculty-details/<int:manuscript_id>/', views.faculty_detail_view, name='faculty_detail'),
    path('faculty-page/', views.faculty_upload_manuscript, name='faculty_upload_page'),
    path('faculty-finalize/<int:manuscript_id>/', views.faculty_final_page, name='faculty_final_page'),
    #Manuscript
    path('upload/', views.upload_manuscript, name='manuscript_upload_page'),
    path('manuscripts/<int:manuscript_id>/', views.view_manuscript, name='view_manuscript'),
    path('finalize/<int:manuscript_id>/', views.final_manuscript_page, name='final_manuscript_page'),
    path('manuscript-search/', views.manuscript_search_page, name='manuscript_search_page'),
    path('request-manuscript/<int:manuscript_id>/', views.request_access, name='request_access'),
    path('view_pdf/<int:manuscript_id>/', views.view_pdf_manuscript, name='view_pdf_manuscript'),
    path('delete_unpublished_manuscripts/', views.delete_unpublished_manuscripts, name='delete_unpublished_manuscripts'),
    #Request Access
    path('manuscript-access-requests/', views.manuscript_access_requests, name='manuscript_access_requests'),
    path('manage-access-request/', views.manage_access_request, name='manage_access_request'),
    path('request-access/<int:manuscript_id>/', views.request_access, name='request_access'),
    #User to verify
    path('adviser-request/', views.request_adviser_view, name='adviser_request'),
    path('adviser-request-success/', views.success_request_view, name='adviser_request_success'),
    #adviser
    path('adviser-approve-student/', views.approve_student_view, name='adviser_approve_student'),
    path('adviser-manuscripts/', views.adviser_manuscript, name='adviser_manuscript'),
    path('adviser-review/<int:manuscript_id>/', views.adviser_review, name='adviser_review'),
    #admin
    path('manage-users/', views.ManageAdviser, name='manage_users'),
    path('manage-dashboard/', views.dashboard_page, name='dashboard_page'),
    path('manage-program/', views.manage_program, name='manage_program'),
    path('manage-category/', views.manage_category, name='manage_category'),
    path('manage-batch/', views.manage_batch, name='manage_batch'),
    path('manage-type/', views.manage_type, name='manage_type'),
    #AJAX
    path('continue-scanning/<int:manuscript_id>/', views.continue_scanning, name='continue_scanning'),
    path('faculty-continue-scanning/<int:manuscript_id>/', views.faculty_continue_scanning, name='faculty_continue_scanning'),
    path('program/check-duplicate/', views.check_program_duplicate, name='check_program_duplicate'),
    path('category/check-duplicate/', views.check_duplicate_category, name='check_duplicate_category'),
    path('manuscripttype/check-duplicate/', views.check_duplicate_manuscripttype, name='check_duplicate_manuscripttype'),

    #Student
    path('my-manuscripts/', views.student_manuscripts_view, name='student_manuscripts'),
    path('my-access-requests/', views.student_access_requests, name='student_access_requests'),
    path('manuscripts-details/<int:manuscript_id>/', views.manuscript_detail_view, name='manuscript_detail'),
    #CRUD
    path('edit-category/<int:category_id>/', views.edit_category, name='edit_category'),
    path('edit-program/<int:program_id>/', views.edit_program, name='edit_program'),
    path('adviser/edit/<int:adviser_id>/', views.edit_adviser, name='edit_adviser'),
    path('edit-type/<int:type_id>/', views.edit_type, name='edit_type'),
    path('create-adviser/', views.create_adviser, name='create_adviser'),
    path('program/create/', views.create_program, name='create_program'),
    path('category/create/', views.create_category, name='create_category'),
    path('manuscripttype/create/', views.create_manuscripttype, name='create_manuscripttype'),
    path('delete-manuscript/<int:manuscript_id>/', views.delete_manuscript, name='delete_manuscript'),

    #Redirecting
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('activate/<uidb64>/<token>/', views.activate_account, name='activate_account'),
    #Visitor Flow
    path('landingpage/', views.index_view, name='index'),
    path('search/', views.visitor_search_manuscripts, name='visitor_search_manuscripts'),
    path('manuscript/<int:manuscript_id>/', views.visitor_manuscript_detail, name='visitor_manuscript_detail'),


] 