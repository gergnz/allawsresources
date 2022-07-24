$(document).ready(function() {
  $('#allaccounts').DataTable( {
    "scrollX": true,
    "columnDefs": [
      {className: "text-center align-middle", targets: [3]},
    ]
  });
  $('.actions').click(function(event){
    var href = this.href;
    event.preventDefault();
    let iframe = document.createElement("iframe");
    iframe.src = "https://signin.aws.amazon.com/oauth?Action=logout";
    iframe.style.display = 'none';
    document.body.appendChild(iframe);
    window.location = href;
  });
});
