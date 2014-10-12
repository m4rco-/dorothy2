$(function() {

    $('#menu-bar').css('opacity', '0.955');

    var selectedArray = [];

    $('#hexdump span[data-hex-id]').dblclick(function () {
        $('span').removeClass('ui-selected');
        var string = $(this).text();

        $('#hexdump span[data-hex-id]').each(function (index) {
            if ($(this).text() == string) {
                var tempID = $(this).attr('data-hex-id');
                $(this).addClass('ui-selected');
                $('span[data-string-id="'+tempID+'"]').addClass('ui-selected');
            };
        });
    });


    $("#hexdump").selectable({
        autoRefresh: true,
        filter: 'span[data-hex-id]',
        selected: function(event, ui) {
            $('#hexdump span.ui-selecting').removeClass('ui-selecting').addClass('ui-selected');
            var stringId = ui.selected.attributes[0].value;

            if (selectedArray.indexOf(stringId) == -1) {
                selectedArray.push(stringId);
            };

            $('span[data-string-id="'+stringId+'"]').addClass('ui-selected');
        },
        unselected: function(event, ui) {
            var stringId = ui.unselected.attributes[0].value;

            $('span[data-string-id="'+stringId+'"]').removeClass('ui-selected');

            selectedArray.splice(selectedArray.indexOf(stringId), 1);
        }
    });

    hexdump(hValue().base, hValue().width, hValue().byteGrouping, hValue().numbers, hValue().html, hValue().ascii);
});