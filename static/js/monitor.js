var certificate_panel = $("#CertificatePanel");
var domain_panel = $("#DomainPanel");
var ip_panel = $("#IpPanel");
var alert_panel = $("#AlertPanel");

var certificate_url = "/monitors/view_certificates";
var domain_url = "/monitors/view_domains";
var ip_url = "/monitors/view_ips";
var alert_url = "/monitors/view_alerts";

var main_content = $("#content");


function initialize_datatable(table_element) {
    $(table_element).dataTable({
        "iDisplayLength":  25,
        "info":            false,
        "bLengthChange":   false,
        "bFilter":         true
    });
}


// Load a specified panel section with a given URL
function load_panel(target_panel, target_url) {
    $.ajax({
        url: target_url,
        type: "GET",
        success:function(content){
            // Load ajax results into target panel and identify item count
            target_panel.html(content);
            var panel_count = target_panel.find('table[data-count]').attr('data-count');

            var panel_table = target_panel.find('table').attr('id');
            if (panel_table !== undefined) { initialize_datatable("#"+panel_table); }

            // Find corresponding tab list header item for badge population
            var panel_tab = $('ul[role=tablist]').find('a[href=#' + target_panel.attr('id') + ']').find('span.badge');
            panel_tab.text(panel_count);
        }
    });
}


function get_active_panel_choices() {
    var active_panel = main_content.find("li.active").children("a").attr("href");
    var addData = $(active_panel).find("form").serializeArray();
    addData.shift();
    return addData;
}


$(document).ready(function(){
   load_panel(certificate_panel, certificate_url); 
   load_panel(domain_panel, domain_url);
   load_panel(ip_panel, ip_url);
   load_panel(alert_panel, alert_url);
});


$(".modal-body").on('submit', 'form', function(event) {
    // Capture form submission event within modal content
    event.preventDefault();

    // Grab reference to form within event context
    var form = $(this);

    // convert form to array and push additional params
    var data = form.serializeArray();

    if (form.hasClass("choice_selector")) {

        var addData = get_active_panel_choices();

        $.each(addData, function( index, value ) {
            data.push(value);
        });
    }

    var formData = $.param(data);
    var formURL = form.attr("action");
    var formMethod = form.attr("method");

    $.ajax({
        type: formMethod,
        url: formURL,
        data: formData,
        success: function(response) {

            if (form.hasClass("no-refresh")) {
                form.closest(".modal-body").html(response)
            } else {
                document.open();
                document.write(response);
                document.close();
            }
        }
    });
});


$(".modal-content").on('click', 'button[data-link]', function() {

    var form = $(this).siblings("form");
    var formURL = $(this).attr("data-link");

    // convert form to array and push additional params
    var data = form.serializeArray();

    if (form.hasClass("choice_selector")) {

        var addData = get_active_panel_choices();

        $.each(addData, function( index, value ) {
            data.push(value);
        });
    }

    var formData = $.param(data);
    var formMethod = form.attr("method");

    $.ajax({
        type: formMethod,
        url: formURL,
        data: formData,
        success: function(response) {

            if (form.hasClass("no-refresh")) {
                var target = form.closest(".modal-body");
                $(target).html(response);
                $(target).find('.selectpicker').selectpicker();
            } else {
                document.open();
                document.write(response);
                document.close();
            }
        }
    });
});


$(document).on( "click", "button[data-toggle=modal]", function() {

    // Grab reference to link within event context
    var link = $(this).attr("data-link");
    var target = $(this).attr("data-target");

    $(target).find(".modal-body").load(link, function() {
        $(target).find('.selectpicker').selectpicker();
    });
});

$(document).on( "click", "a[data-toggle=modal]", function() {
    // Grab reference to link within event context
    var link = $(this).attr("data-link");
    var target = $(this).attr("data-target");
    $(target).find(".modal-body").load(link, function() {
        console.log("I don't think we need to do anything here. It's a callback once loading is complete.");
    });
});
// End modal functions and events //
