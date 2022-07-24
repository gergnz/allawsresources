$(document).ready(function () {
  var uuid = uuidv4();
  $("#externalid").val(uuid);
  $("#create").click(function () {
    var organisation = $("#organisation").val();
    var externalid = $("#externalid").val();
    var stsrole = $("#stsrole").val();
    var scanrole = $("#scanrole").val();
    var csrf = $("#csrf").val();
    data = "organisation=" + organisation + "&stsrole=" + stsrole + "&externalid=" + externalid + "&_csrf_token=" + csrf + "&scanrole=" + scanrole;
    $.ajax({
      type: 'POST',
      url: "/addaws",
      cache: false,
      data,
      success: function (data, status, xhr) {
        location.reload();
      },
      error: function (data, status, xhr) {
        console.log(status);
      }
    });
  });
});

function printit(value, index, array) {
  return "        - \"arn:aws:iam::aws:policy/" + value + "\""
}

$(document).ready(function () {
  $('.testaccess').click(function () {
    var href = $(this).attr('href');
    var organisation = href.split(';')[1];
    var self = this;
    $.get('/testaccess?' + organisation, function (response) {
      console.log(response.result);
      if (response.result === 'success') {
        $(self).removeClass('primary');
        $(self).removeClass('bi-question-lg');
        $(self).addClass('bi-check-lg');
        $(self).addClass('text-success');
      } else {
        $(self).removeClass('primary');
        $(self).removeClass('bi-question-lg');
        $(self).addClass('bi-x-lg');
        $(self).addClass('text-danger');
      }
    });
  });

  $('.delete-account').click(function () {
    var organisation = $(this).data('organisation');
    $("#delete-organisation").val(organisation);
  });

  $('#deleteModalBtn').click(function () {
    var organisation = $("#delete-organisation").val();
    window.location.href = '/delaws?organisation=' + organisation;
  });

});

$(document).ready(function () {
  $('#actstable').DataTable({
    "scrollX": true
  });
});
