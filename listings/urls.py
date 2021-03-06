from django.urls import path
from . import views
from django.conf.urls import url

urlpatterns = [
    path('', views.index, name='listings'),
    path('<int:listing_id>', views.listing, name='listing'),
    path('search', views.search, name='search'),
    path('<path:image>', views.panorama, name='panorama'),
]