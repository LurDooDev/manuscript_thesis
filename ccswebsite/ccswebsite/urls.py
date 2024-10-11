from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', RedirectView.as_view(url='authentication/login', permanent=False)),  
    path('authentication/', include('authentication.urls')),
]
