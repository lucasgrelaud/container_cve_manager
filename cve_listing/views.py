from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.contrib.auth.decorators import login_required

from .rest_client import HarborAPI
from .models import AllowedCVE


def index(request):
    context = dict()
    context['select'] = AllowedCVE.Reason
    return render(request, 'cve_listing/index.html', context)

@login_required(login_url='/login')
def manage_allowlist(request):
    context = dict()
    context['allowed_cve'] = AllowedCVE.objects.all()
    return render(request, 'cve_listing/manage-allowlist.html', context)

@login_required(login_url='/login')
def edit_allowed_cve(request, cve_id):
    context = dict()
    code = 418
    try:
        context['allowed_cve'] = AllowedCVE.objects.get(pk=cve_id)
        context['select'] = AllowedCVE.Reason

        if request.method == 'POST':
            context['allowed_cve'].added_by = request.POST.get("added_by")
            context['allowed_cve'].date = request.POST.get("date")
            context['allowed_cve'].reason = request.POST.get("reason")
            context['allowed_cve'].comment = request.POST.get("comment")
            context['allowed_cve'].save()
            context['result'] = {'state': 'success', 'message': 'CVE successfully update!'}
        code = 200

    except ObjectDoesNotExist:
        context['result'] = {'state': 'error', 'message': 'The CVE does not exist'}
        code = 500

    return render(request, 'cve_listing/edit-allowed-cve.html', context, status=code)

@login_required(login_url='/login')
def delete_allowed_cve(request, cve_id):
    context = dict()
    code = 418

    try:
        context['allowed_cve'] = AllowedCVE.objects.get(pk=cve_id)

        if request.method == 'POST':
            context['allowed_cve'].delete()
            context['result'] = {'state': 'success', 'message': 'CVE successfully deleted!'}
        code = 200

    except ObjectDoesNotExist:
        context['result'] = {'state': 'error', 'message': 'The CVE does not exist'}
        code = 500

    return render(request, 'cve_listing/delete-allowed-cve.html', context, status=code)


def export_allowlist(request):
    response: str = str()
    for reason in AllowedCVE.Reason:
        response += '# ' + reason.label + '\n'
        for cve in AllowedCVE.objects.filter(reason=reason):
            response += cve.cve_id + "\n"
        response += "\n"

    if request.GET.get('base_image') and request.GET.get('tag'):
        harbor_api: HarborAPI = HarborAPI()
        base_cve = harbor_api.get_base_image_vulnerabilities(request.GET.get('base_image'), request.GET.get('tag'))
        response += '# CVE linked to base image : ' + request.GET.get('base_image') + '@' + request.GET.get(
            'tag') + '\n'
        for cve in base_cve:
            response += cve['id'] + "\n"
    return HttpResponse(response, content_type='text/plain')


def logout_view(request):
    logout(request)
    return redirect("cve_listing:index")


def login_view(request):
    context = dict()
    if request.method == 'POST':
        form = AuthenticationForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('cve_listing:index')
            else:
                context['result'] = {'state': 'error', 'message': 'Invalid username or password.'}
        else:
            context['result'] = {'state': 'error', 'message': 'Invalid username or password.'}
    return render(request, 'cve_listing/login.html')


# API endpoints
def api_list_base_image(request):
    harbor_api: HarborAPI = HarborAPI()
    return JsonResponse(harbor_api.get_base_image_list())


def api_list_base_image_tag(request, image_name):
    harbor_api: HarborAPI = HarborAPI()
    return JsonResponse(harbor_api.get_base_image_tag(image_name))


def api_list_base_image_vulnerabilities(request, image_name, image_tag):
    harbor_api: HarborAPI = HarborAPI()
    cve_list = harbor_api.get_base_image_vulnerabilities(image_name, image_tag)
    allowed_cves: list = list()
    for cve in AllowedCVE.objects.all():
        allowed_cves.append(cve.cve_id)

    for cve in cve_list:
        if cve['id'] in allowed_cves:
            cve['allowed'] = 'True'
        else:
            cve['allowed'] = 'False'

    if request.GET.get('not_fixed') and request.GET.get('not_fixed') == 'false':
        cve_list = [cve for cve in cve_list if cve['fix_version']]

    if request.GET.get('not_allowed') and request.GET.get('not_allowed') == 'false':
        cve_list = [cve for cve in cve_list if cve['allowed'] != 'True']

    return JsonResponse(cve_list, safe=False)


def api_list_projects(request):
    harbor_api: HarborAPI = HarborAPI()
    return JsonResponse(harbor_api.get_project_list())


def api_list_image(request, project_name):
    harbor_api: HarborAPI = HarborAPI()
    return JsonResponse(harbor_api.get_image_list(project_name))


def api_list_image_tag(request, project_name, image_name):
    harbor_api: HarborAPI = HarborAPI()
    return JsonResponse(harbor_api.get_image_tag(project_name, image_name))


def api_list_image_vulnerabilities(request, project_name, image_name, image_tag):
    harbor_api: HarborAPI = HarborAPI()
    cve_list = harbor_api.get_image_vulnerabilities(project_name, image_name, image_tag)
    allowed_cves: list = list()
    for cve in AllowedCVE.objects.all():
        allowed_cves.append(cve.cve_id)

    for cve in cve_list:
        if cve['id'] in allowed_cves:
            cve['allowed'] = 'True'
        else:
            cve['allowed'] = 'False'

    if request.GET.get('base_image') and request.GET.get('tag'):
        base_cve = harbor_api.get_base_image_vulnerabilities(request.GET.get('base_image'), request.GET.get('tag'))
        cve_list = [cve for cve in cve_list if cve['id'] in list(map(lambda cve: cve['id'], base_cve))]

    if request.GET.get('not_fixed') and request.GET.get('not_fixed') == 'false':
        cve_list = [cve for cve in cve_list if cve['fix_version']]

    if request.GET.get('not_allowed') and request.GET.get('not_allowed') == 'false':
        cve_list = [cve for cve in cve_list if cve['allowed'] != 'True']

    return JsonResponse(cve_list, safe=False)


def api_list_allowed_cve(request):
    if request.method == 'GET':
        cve_list: list = list()
        for cve in AllowedCVE.objects.all():
            cve_list.append(cve.cve_id)
        return JsonResponse(cve_list, safe=False)
    elif request.method == 'POST':
        try:
            raw_cve = AllowedCVE()
            raw_cve.cve_id = request.POST.get("cve_id")
            raw_cve.added_by = request.POST.get("added_by")
            raw_cve.date = request.POST.get("date")
            raw_cve.reason = request.POST.get("reason")
            raw_cve.comment = request.POST.get("comment")
            raw_cve.save()
            return JsonResponse({'result': raw_cve.cve_id + ' has been created'})
        except ValidationError:
            cve = {
                'error': 'An error occurred while saving the cve',
                'reason': 'ValidationError'
            }
            return JsonResponse(cve, status=500)
    else:
        return JsonResponse({}, status=500)


def api_allowed_cve_details(request, cve_id):
    if request.method == 'GET':
        cve: dict
        try:
            raw_cve = AllowedCVE.objects.get(pk=cve_id)
            cve = {
                'id': raw_cve.cve_id,
                'added_by': raw_cve.added_by,
                'date': raw_cve.date,
                'reason': raw_cve.reason,
                'comment': raw_cve.comment
            }
            return JsonResponse(cve)
        except ObjectDoesNotExist:
            cve = {
                'error': 'The requested CVE is not in AllowList',
                'reason': 'objectdoesnotexist'
            }
            return JsonResponse(cve, status=404)
    elif request.method == 'POST':
        try:
            raw_cve = AllowedCVE.objects.get(pk=cve_id)
            raw_cve.added_by = request.POST.get("added_by")
            raw_cve.date = request.POST.get("date")
            raw_cve.reason = request.POST.get("reason")
            raw_cve.comment = request.POST.get("comment")
            raw_cve.save()

            return JsonResponse({'result': cve_id + ' has been updated'})

        except ObjectDoesNotExist:
            cve = {
                'error': 'The requested CVE is not in AllowList',
                'reason': 'objectdoesnotexist'
            }
            return JsonResponse(cve, status=404)

    else:
        return JsonResponse({}, status=500)


def api_delete_allowed_cve(request, cve_id):
    if request.method == 'POST':
        try:
            raw_cve = AllowedCVE.objects.get(pk=cve_id)
            raw_cve.delete()
            return JsonResponse({'result': cve_id + ' has been deleted'})

        except ObjectDoesNotExist:
            cve = {
                'error': 'The requested CVE is not in AllowList',
                'reason': 'objectdoesnotexist'
            }
            return JsonResponse(cve, status=404)
    else:
        return JsonResponse({}, status=500)
