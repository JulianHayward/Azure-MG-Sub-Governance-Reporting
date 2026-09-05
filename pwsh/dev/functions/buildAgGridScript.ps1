function buildAgGridScript {
    <#
    .SYNOPSIS
    Builds the html and script of an AG Grid table: dictionary encoded rows, a grid definition that the pop out
    window can reuse and the create/export/popout glue.

    .DESCRIPTION
    A column definition is a hashtable with the keys:
      header          - the column header
      property        - the property of a row object that is used for sorting, filtering and the csv export
      htmlProperty    - optional, the property that is rendered instead of 'property'
      htmlValueScript - optional, a scriptblock receiving the row object that produces the value of 'htmlProperty'
      filter          - optional, one of 'select', 'number', 'date'
      hide            - optional, the column is available but not shown
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $HtmlTableId,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]
        $Rows,

        [Parameter(Mandatory)]
        [object[]]
        $ColumnDefinitions,

        [Parameter(Mandatory)]
        [string]
        $PopoutTitle,

        [int]
        $GridHeight = 0
    )

    if ($GridHeight -le 0) {
        $GridHeight = [math]::Min(600, [math]::Max(220, 130 + $Rows.Count * 42))
    }
    $gridPopoutTitle = $PopoutTitle.Replace('\', '\\').Replace("'", "\'")

    $gridColumns = [System.Collections.Generic.List[string]]::new()
    $gridColumnScripts = [System.Collections.Generic.List[scriptblock]]::new()
    foreach ($columnDefinition in $ColumnDefinitions) {
        if ($columnDefinition.htmlProperty) {
            $gridColumns.Add($columnDefinition.htmlProperty)
            $gridColumnScripts.Add($columnDefinition.htmlValueScript)
        }
        $gridColumns.Add($columnDefinition.property)
        $gridColumnScripts.Add($null)
    }
    $gridColumnCount = $gridColumns.Count

    $gridColumnDefsJs = foreach ($columnDefinition in $ColumnDefinitions) {
        $gridValueIndex = $gridColumns.IndexOf($columnDefinition.property)
        $gridColumnDefParts = [System.Collections.Generic.List[string]]::new()
        $gridColumnDefParts.Add("headerName: '$($columnDefinition.header)'")
        $gridColumnDefParts.Add("colId: '$($columnDefinition.property)'")
        if ($columnDefinition.filter -eq 'number') {
            $gridColumnDefParts.Add("valueGetter: agvColumnNumberValueGetter(agvRowData, $gridValueIndex)")
            $gridColumnDefParts.Add("cellRenderer: agvColumnTextRenderer(agvRowData, $gridValueIndex, agvHighlighter)")
            $gridColumnDefParts.Add("cellDataType: 'number'")
            $gridColumnDefParts.Add("filter: 'agNumberColumnFilter'")
        }
        else {
            $gridColumnDefParts.Add("valueGetter: agvColumnValueGetter(agvRowData, $gridValueIndex)")
        }
        if ($columnDefinition.htmlProperty) {
            $gridColumnDefParts.Add("cellRenderer: agvColumnHtmlRenderer(agvRowData, $($gridColumns.IndexOf($columnDefinition.htmlProperty)), agvHighlighter)")
        }
        if ($columnDefinition.filter -eq 'select') {
            $gridColumnDefParts.Add('floatingFilterComponent: agvSelectFloatingFilter')
            $gridColumnDefParts.Add("floatingFilterComponentParams: { values: agvRowData.dictionaries[$gridValueIndex] }")
            $gridColumnDefParts.Add('suppressFloatingFilterButton: true')
        }
        if ($columnDefinition.filter -eq 'date') {
            $gridColumnDefParts.Add("filter: 'agDateColumnFilter'")
            $gridColumnDefParts.Add('filterParams: agvDateFilterParams')
            $gridColumnDefParts.Add('comparator: agvDateSortComparator')
        }
        if ($columnDefinition.hide) {
            $gridColumnDefParts.Add('hide: true')
        }
        "        { $($gridColumnDefParts -join ', ') }"
    }
    $gridColumnDefsJs = $gridColumnDefsJs -join ",$([System.Environment]::NewLine)"

    #per column dictionary of distinct values, a row then only holds the integer indexes into those dictionaries
    $gridDictionaries = New-Object 'System.Collections.Generic.List[string][]' $gridColumnCount
    $gridMaps = New-Object 'System.Collections.Generic.Dictionary[string,int][]' $gridColumnCount
    for ($gridColumn = 0; $gridColumn -lt $gridColumnCount; $gridColumn++) {
        $gridDictionaries[$gridColumn] = [System.Collections.Generic.List[string]]::new()
        $gridMaps[$gridColumn] = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
    }

    $gridRowsBuilder = [System.Text.StringBuilder]::new()
    $gridFirstRow = $true
    foreach ($gridEntry in $Rows) {
        if ($gridFirstRow) { $gridFirstRow = $false } else { [void]$gridRowsBuilder.Append(',') }
        [void]$gridRowsBuilder.Append('[')
        for ($gridColumn = 0; $gridColumn -lt $gridColumnCount; $gridColumn++) {
            if ($null -ne $gridColumnScripts[$gridColumn]) {
                $gridValue = [string](& $gridColumnScripts[$gridColumn] $gridEntry)
            }
            else {
                $gridRawValue = $gridEntry.($gridColumns[$gridColumn])
                if ($gridRawValue -is [bool]) {
                    $gridValue = if ($gridRawValue) { 'true' } else { 'false' }
                }
                else {
                    $gridValue = [string]$gridRawValue
                }
            }
            $gridDictionaryIndex = 0
            if (-not $gridMaps[$gridColumn].TryGetValue($gridValue, [ref]$gridDictionaryIndex)) {
                $gridDictionaryIndex = $gridDictionaries[$gridColumn].Count
                $gridMaps[$gridColumn][$gridValue] = $gridDictionaryIndex
                $gridDictionaries[$gridColumn].Add($gridValue)
            }
            if ($gridColumn -gt 0) { [void]$gridRowsBuilder.Append(',') }
            [void]$gridRowsBuilder.Append($gridDictionaryIndex)
        }
        [void]$gridRowsBuilder.Append(']')
    }

    #the dictionaries hold every string of the data set, EscapeHtml keeps '<' out of the enclosing script element
    $gridDictionariesArray = New-Object 'object[]' $gridColumnCount
    for ($gridColumn = 0; $gridColumn -lt $gridColumnCount; $gridColumn++) {
        $gridDictionariesArray[$gridColumn] = $gridDictionaries[$gridColumn].ToArray()
    }
    $gridCompressed = compressGridDictionaries -Dictionaries $gridDictionariesArray
    $gridDictionariesJson = ConvertTo-Json -InputObject $gridCompressed.dictionaries -Compress -Depth 3 -EscapeHandling EscapeHtml
    $gridFragmentsJson = ConvertTo-Json -InputObject $gridCompressed.fragments -Compress -EscapeHandling EscapeHtml
    $gridColumnsJson = ConvertTo-Json -InputObject $gridColumns.ToArray() -Compress -EscapeHandling EscapeHtml

    return @"
<div id="$HtmlTableId" class="ag-theme-quartz" style="height:$($GridHeight)px;width:100%;"></div>
<script>
var rowData4$($HtmlTableId) = agvExpandDictionaries({rows:[
$($gridRowsBuilder.ToString())
],
dictionaries: $($gridDictionariesJson),
fragments: $($gridFragmentsJson),
columns: $($gridColumnsJson)
});
</script>
<script id="agvGridDef4$($HtmlTableId)">
//factory, so that the pop out window can build the very same grid in its own document
function agvGridOptions4$($HtmlTableId)(agvHighlighter, agvRowData, agvGridElement) {
    //the column index passed to the getters/renderers must match the column order of the emitted rowData
    return {
    rowData: agvRowData.rows,
    columnDefs: [
$($gridColumnDefsJs)
    ],
    defaultColDef: {
        minWidth: 90,
        maxWidth: 420,
        sortable: true,
        resizable: true,
        //every value is a string, without this AG Grid would infer the type from the data and e.g. render 'true'/'false' as a checkbox
        cellDataType: 'text',
        filter: 'agTextColumnFilter',
        floatingFilter: true,
        //no truncation: columns are sized to their content, anything beyond maxWidth wraps
        wrapText: true,
        autoHeight: true,
        wrapHeaderText: true,
        autoHeaderHeight: true,
        //renders the plain cell value html encoded and wraps the text filter matches in <mark>
        cellRenderer: function (params) { return agvHighlighter.text(params.value, params.column.getColId()); }
    },
    autoSizeStrategy: { type: 'fitCellContents' },
    pagination: true,
    paginationPageSize: 100,
    paginationPageSizeSelector: [10, 30, 50, 100, 250, 500, 1000],
    enableCellTextSelection: true,
    ensureDomOrder: true,
    onFirstDataRendered: function (event) {
        agvAddResetFiltersButton(event.api, agvGridElement);
    },
    onFilterChanged: function (event) {
        var changed = agvHighlighter.update(event.api.getFilterModel());
        if (changed.length) {
            //refresh all rows of the changed columns so that the marks are also updated off screen
            event.api.refreshCells({ columns: changed, force: true });
        }
    }
    };
}
</script>
<script>
function createag$($HtmlTableId)() {
    if (window.helperag$($HtmlTableId) === 1) { return; }
    window.helperag$($HtmlTableId) = 1;
    var element = document.getElementById('$HtmlTableId');
    window.api4$($HtmlTableId) = agGrid.createGrid(element, agvGridOptions4$($HtmlTableId)(agvCreateHighlighter(), rowData4$($HtmlTableId), element));
}
function loadag$($HtmlTableId)() {
    //deferred, the collapsible content is made visible by the click handler that runs after this one
    setTimeout(createag$($HtmlTableId), 0);
}
function exportag$($HtmlTableId)(separator) {
    createag$($HtmlTableId)();
    window.api4$($HtmlTableId).exportDataAsCsv({ columnSeparator: separator, fileName: 'export_$($HtmlTableId)_' + new Date().toLocaleDateString('en-CA') + '.csv' });
}
function popoutag$($HtmlTableId)() {
    agvPopoutGrid('$gridPopoutTitle', 'agvGridDef4$($HtmlTableId)', 'agvGridOptions4$($HtmlTableId)', 'rowData4$($HtmlTableId)');
}
</script>
"@
}
