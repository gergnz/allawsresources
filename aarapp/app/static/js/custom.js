$(document).ready(function() {
  $('#alertclose').click(function(){
    $('.alert').fadeTo(0, 500).slideUp(500, function(){
      $('.alert').slideUp(500);
    });
  });
  $('.navbar-toggler').click(function(){
    $('.navbar-collapse').collapse('toggle');  
  });
});

$('#refresh').click(function() {
    location.reload();
});
