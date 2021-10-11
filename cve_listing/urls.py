from django.urls import path

from . import views

app_name = "cve_listing"
urlpatterns = [
    path('', views.index, name='index'),
    path('manage-allowlist', views.manage_allowlist, name='manage-allowlist'),
    path('manage-allowlist/<str:cve_id>', views.edit_allowed_cve, name='edit_allowed_cve'),
    path('manage-allowlist/<str:cve_id>/delete', views.delete_allowed_cve, name='delete_allowed_cve'),
    path('export/allowlist', views.export_allowlist, name="export_allowlist"),
    path('logout', views.logout_view, name="logout"),
    path('login', views.login_view, name="login"),

    path('api/base-image', views.api_list_base_image),
    path('api/base-image/<str:image_name>/tag', views.api_list_base_image_tag),
    path('api/base-image/<str:image_name>/tag/<str:image_tag>/vulnerabilities',
         views.api_list_base_image_vulnerabilities),

    path('api/project', views.api_list_projects),
    path('api/project/<str:project_name>/image', views.api_list_image),
    path('api/project/<str:project_name>/image/<str:image_name>/tag', views.api_list_image_tag),
    path('api/project/<str:project_name>/image/<str:image_name>/tag/<str:image_tag>/vulnerabilities',
         views.api_list_image_vulnerabilities),

    path('api/allowed-cve', views.api_list_allowed_cve),
    path('api/allowed-cve/<str:cve_id>', views.api_allowed_cve_details),
    path('api/allowed-cve/<str:cve_id>/delete', views.api_delete_allowed_cve)

]
