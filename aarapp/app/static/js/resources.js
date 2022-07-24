$(document).ready(function() {
    $('#allawsresources thead tr').clone(true).appendTo( '#allawsresources thead' );
    $('#allawsresources thead tr:eq(1) th').each( function (i) {
      var title = $(this).text();
      var size = 10;
      if ( title.length > 4 ) {
        size = title.length;
      }
      $(this).html( '<input type="text" placeholder="'+title+'" size="'+size+'" />' );

      $( 'input', this ).on( 'keyup change', function () {
          if ( table.column(i).search() !== this.value ) {
              table
                  .column(i)
                  .search( this.value )
                  .draw();
          }
      } );
    } );
    var table = $('#allawsresources').DataTable( {
        "scrollX": true,
        responsive: true,
        orderCellsTop: true,
        fixedHeader: true,
        dom: 'RSPQBfrtipl',
        lengthMenu: [20, 50, 100, 200, 500, 1000, 2000],
        buttons: {
          buttons: [
            { extend: 'copy', className: 'btn btn-primary' },
            { extend: 'csv', className: 'btn btn-primary' },
            { extend: 'excel', className: 'btn btn-primary' }
          ]
        }
    } );
} );
