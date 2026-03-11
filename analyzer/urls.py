from django.urls import path
from . import views

urlpatterns = [
    path("", views.upload_view, name="upload"),
    path("result/<str:run_id>/", views.result_view, name="result"),
    path("download/<str:run_id>/pdf/", views.download_pdf, name="download_pdf"),
]