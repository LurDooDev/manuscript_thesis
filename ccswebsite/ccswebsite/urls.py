from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('ccsrepo_app.urls')),  # This includes the app's URLs
]
