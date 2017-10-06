from __future__ import absolute_import
from __future__ import unicode_literals

import tempfile
from datetime import datetime, timedelta

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.core.urlresolvers import reverse
from django.template.loader import render_to_string
from django.utils.http import urlencode
from django.utils import timezone as tz
from celery.utils.log import get_task_logger
from celery.decorators import task
from dojo.models import Finding, Test, Engagement
from pytz import timezone, utc
from django.forms.models import model_to_dict

import pdfkit
import socket
from dojo.celery import app
from dojo.reports.widgets import report_widget_factory
from dojo.utils import add_comment, add_epic, add_issue, update_epic, update_issue, \
                        close_epic, get_system_setting, create_notification
from dojo.tintri.zap.buildbot import do_zap_scan
from dojo.tintri.zap.parser import parse_zap_result

logger = get_task_logger(__name__)

localtz = timezone(get_system_setting('time_zone'))

def self_IP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

@app.task(bind=True)
def add_alerts(self, runinterval):
    print "adding alert ..."
    now = tz.now()

    upcoming_engagements = Engagement.objects.filter(target_start__gt=now+timedelta(days=3),target_start__lt=now+timedelta(days=3)+runinterval).order_by('target_start')
    for engagement in upcoming_engagements:
        create_notification(event='upcoming_engagement',
                           title='Upcoming engagement: %s' % engagement.name,
                           engagement=engagement,
                           recipients=[engagement.lead],
                           url=request.build_absolute_uri(reverse('view_engagement', args=(engagement.id,))))

    stale_engagements = Engagement.objects.filter(
        target_start__gt=now-runinterval,
        target_end__lt=now,
        status='In Progress').order_by('-target_end')
    for eng in stale_engagements:
        create_notification(event='stale_engagement', 
                           title='Stale Engagement: %s' % eng.name,
                           description='The engagement "%s" is stale. Target end was %s.' % (eng.name, eng.target_end.strftime("%b. %d, %Y")),
                           url=reverse('view_engagement', args=(eng.id,)),
                           recipients=[eng.lead])


@app.task(bind=True)
def async_pdf_report(self,
                     report=None,
                     template="None",
                     filename='report.pdf',
                     report_title=None,
                     report_subtitle=None,
                     report_info=None,
                     context={},
                     uri=None):
    xsl_style_sheet = settings.DOJO_ROOT + "/static/dojo/xsl/pdf_toc.xsl"
    x = urlencode({'title': report_title,
                   'subtitle': report_subtitle,
                   'info': report_info})

    cover = context['host'] + reverse(
        'report_cover_page') + "?" + x

    config = pdfkit.configuration(wkhtmltopdf=settings.WKHTMLTOPDF_PATH)
    try:
        report.task_id = async_pdf_report.request.id
        report.save()
        bytes = render_to_string(template, context)
        itoc = context['include_table_of_contents']
        if itoc:
            toc = {'xsl-style-sheet': xsl_style_sheet}
        else:
            toc = None
        pdf = pdfkit.from_string(bytes,
                                 False,
                                 configuration=config,
                                 cover=cover,
                                 toc=toc)
        if report.file.name:
            with open(report.file.path, 'w') as f:
                f.write(pdf)
            f.close()
        else:
            f = ContentFile(pdf)
            report.file.save(filename, f)
        report.status = 'success'
        report.done_datetime = datetime.now(tz=localtz)
        report.save()

        create_notification(event='report_created', title='Report created', description='The report "%s" is ready.' % report.name, url=uri, report=report, objowner=report.requester)
    except Exception as e:
        report.status = 'error'
        report.save()
        # email_requester(report, uri, error=e)
        raise e
    return True


@app.task(bind=True)
def async_custom_pdf_report(self,
                            report=None,
                            template="None",
                            filename='report.pdf',
                            host=None,
                            user=None,
                            uri=None,
                            finding_notes=False,
                            finding_images=False):
    config = pdfkit.configuration(wkhtmltopdf=settings.WKHTMLTOPDF_PATH)

    selected_widgets = report_widget_factory(json_data=report.options, request=None, user=user,
                                             finding_notes=finding_notes, finding_images=finding_images, host=host)

    widgets = selected_widgets.values()
    temp = None

    try:
        report.task_id = async_custom_pdf_report.request.id
        report.save()

        toc = None
        toc_depth = 4

        if 'table-of-contents' in selected_widgets:
            xsl_style_sheet_tempalte = "dojo/pdf_toc.xsl"
            temp = tempfile.NamedTemporaryFile()

            toc_settings = selected_widgets['table-of-contents']

            toc_depth = toc_settings.depth
            toc_bytes = render_to_string(xsl_style_sheet_tempalte, {'widgets': widgets,
                                                                    'depth': toc_depth,
                                                                    'title': toc_settings.title})
            temp.write(toc_bytes)
            temp.seek(0)

            toc = {'toc-header-text': toc_settings.title,
                   'xsl-style-sheet': temp.name}

        cover = None
        if 'cover-page' in selected_widgets:
            cp = selected_widgets['cover-page']
            x = urlencode({'title': cp.title,
                           'subtitle': cp.sub_heading,
                           'info': cp.meta_info})
            cover = host + reverse(
                'report_cover_page') + "?" + x
        bytes = render_to_string(template, {'widgets': widgets,
                                            'toc_depth': toc_depth,
                                            'host': host,
                                            'report_name': report.name})
        pdf = pdfkit.from_string(bytes,
                                 False,
                                 configuration=config,
                                 cover=cover,
                                 toc=toc,
                                 )

        if report.file.name:
            with open(report.file.path, 'w') as f:
                f.write(pdf)
            f.close()
        else:
            f = ContentFile(pdf)
            report.file.save(filename, f)
        report.status = 'success'
        report.done_datetime = datetime.now(tz=localtz)
        report.save()

        create_notification(event='report_created', title='Report created', description='The report "%s" is ready.' % report.name, url=uri, report=report, objowner=report.requester)
    except Exception as e:
        report.status = 'error'
        report.save()
        # email_requester(report, uri, error=e)
        raise e
    finally:
        if temp is not None:
            # deleting temp xsl file
            temp.close()

    return True

@task(name='add_issue_task')
def add_issue_task( find, push_to_jira):
    logger.info("add issue task")
    add_issue(find, push_to_jira)

@task(name='update_issue_task')
def update_issue_task(find, old_status, push_to_jira):
    logger.info("add issue task")
    update_issue(find, old_status, push_to_jira)

@task(name='add_epic_task')
def add_epic_task(eng, push_to_jira):
    logger.info("add epic task")
    add_epic(eng, push_to_jira)

@task(name='update_epic_task')
def update_epic_task(eng, push_to_jira):
    logger.info("update epic task")
    update_epic(eng, push_to_jira)

@task(name='close_epic_task')
def close_epic_task(eng, push_to_jira):
    logger.info("close epic task")
    close_epic(eng, push_to_jira)

@task(name='add comment')
def add_comment_task(find, note):
    logger.info("add comment")
    add_comment(find, note)

@app.task(name='async_dedupe')
def async_dedupe(new_finding, *args, **kwargs):
    logger.info("running deduplication")
    eng_findings_cwe = Finding.objects.filter(test__engagement__product=new_finding.test.engagement.product,
                                              cwe=new_finding.cwe).exclude(id=new_finding.id).exclude(cwe=None).exclude(endpoints=None)
    eng_findings_title = Finding.objects.filter(test__engagement__product=new_finding.test.engagement.product,
                                                title=new_finding.title).exclude(id=new_finding.id).exclude(endpoints=None)
    total_findings = eng_findings_cwe | eng_findings_title
    for find in total_findings:
        list1 = new_finding.endpoints.all()
        list2 = find.endpoints.all()
        if all(x in list2 for x in list1):
            find.duplicate = True
            super(Finding, find).save(*args, **kwargs)

@app.task(name='async_false_history')
def async_false_history(new_finding, *args, **kwargs):
    logger.info("running false_history")
    eng_findings_cwe = Finding.objects.filter(test__engagement__product=new_finding.test.engagement.product,
                                              cwe=new_finding.cwe, test__test_type=new_finding.test.test_type,
                                              false_p=True).exclude(
                                              id=new_finding.id).exclude(cwe=None).exclude(endpoints=None)
    eng_findings_title = Finding.objects.filter(test__engagement__product=new_finding.test.engagement.product,
                                                title=new_finding.title, test__test_type=new_finding.test.test_type,
                                                false_p=True).exclude(id=new_finding.id).exclude(endpoints=None)
    total_findings = eng_findings_cwe | eng_findings_title
    if total_findings.count() > 0:
            new_finding.false_p = True
            super(Finding, new_finding).save(*args, **kwargs)


def mark_start_test(test):
    test.target_start = datetime.now(tz=utc)
    test.target_end = None
    test.status = "Scheduled"
    test.percent_complete = 1
    test.save()

@app.task(name='async_schedule_test')
def async_schedule_test(test_id, *args, **kwargs):
    test = Test.objects.get(id=test_id)
    if test.test_tool is None:
        return
    if test.test_type.name == 'ZAP Scan':
        if not test.tags:
            return
        target = test.tags[0].name
        mark_start_test(test)
        status, done = do_zap_scan(test.test_tool.url, target, self_IP(), test_id)
        test.status = status
        print "do_zap_scan returned: ", status, done
        if done:
            test.target_end = datetime.now(tz=utc)
            test.percent_complete = 100
        test.save()
