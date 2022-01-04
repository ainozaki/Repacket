; ModuleID = 'xdp-generated-dump.c'
source_filename = "xdp-generated-dump.c"
target datalayout = "e-m:e-p:64:64-i64:64-n32:64-S128"
target triple = "bpf"

%struct.bpf_map_def = type { i32, i32, i32, i32, i32 }
%struct.S = type { i16, i16 }
%struct.xdp_md = type { i32, i32, i32, i32, i32 }

@perf_map = dso_local global %struct.bpf_map_def { i32 4, i32 4, i32 4, i32 128, i32 0 }, section "maps", align 4, !dbg !0
@__const.xdp_dump_prog.____fmt = private unnamed_addr constant [30 x i8] c"perf_event_output failed: %d\0A\00", align 1
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !23
@__packed = common dso_local local_unnamed_addr global %struct.S zeroinitializer, align 2, !dbg !29
@llvm.used = appending global [3 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (%struct.bpf_map_def* @perf_map to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_dump_prog to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @xdp_dump_prog(%struct.xdp_md* %0) #0 section "xdp_generated" !dbg !62 {
  %2 = alloca %struct.S, align 2
  %3 = alloca [30 x i8], align 1
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !74, metadata !DIExpression()), !dbg !88
  %4 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !89
  %5 = load i32, i32* %4, align 4, !dbg !89, !tbaa !90
  %6 = trunc i32 %5 to i16, !dbg !95
  call void @llvm.dbg.value(metadata i32 %5, metadata !75, metadata !DIExpression()), !dbg !88
  %7 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !96
  %8 = load i32, i32* %7, align 4, !dbg !96, !tbaa !97
  %9 = trunc i32 %8 to i16, !dbg !98
  call void @llvm.dbg.value(metadata i32 %8, metadata !76, metadata !DIExpression()), !dbg !88
  call void @llvm.dbg.value(metadata i64 4294967295, metadata !77, metadata !DIExpression()), !dbg !88
  %10 = bitcast %struct.S* %2 to i8*, !dbg !99
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %10) #3, !dbg !99
  call void @llvm.dbg.declare(metadata %struct.S* %2, metadata !80, metadata !DIExpression()), !dbg !100
  %11 = getelementptr inbounds %struct.S, %struct.S* %2, i64 0, i32 0, !dbg !101
  store i16 -8531, i16* %11, align 2, !dbg !102, !tbaa !103
  %12 = sub i16 %6, %9, !dbg !106
  %13 = getelementptr inbounds %struct.S, %struct.S* %2, i64 0, i32 1, !dbg !107
  store i16 %12, i16* %13, align 2, !dbg !108, !tbaa !109
  %14 = icmp ult i16 %12, 1024, !dbg !110
  %15 = select i1 %14, i16 %12, i16 1024, !dbg !110
  call void @llvm.dbg.value(metadata i16 %15, metadata !78, metadata !DIExpression()), !dbg !88
  %16 = zext i16 %15 to i64, !dbg !111
  %17 = shl nuw nsw i64 %16, 32, !dbg !112
  %18 = or i64 %17, 4294967295, !dbg !113
  call void @llvm.dbg.value(metadata i64 %18, metadata !77, metadata !DIExpression()), !dbg !88
  %19 = bitcast %struct.xdp_md* %0 to i8*, !dbg !114
  %20 = call i32 inttoptr (i64 25 to i32 (i8*, i8*, i64, i8*, i64)*)(i8* %19, i8* bitcast (%struct.bpf_map_def* @perf_map to i8*), i64 %18, i8* nonnull %10, i64 4) #3, !dbg !115
  call void @llvm.dbg.value(metadata i32 %20, metadata !79, metadata !DIExpression()), !dbg !88
  %21 = icmp eq i32 %20, 0, !dbg !116
  br i1 %21, label %25, label %22, !dbg !117

22:                                               ; preds = %1
  %23 = getelementptr inbounds [30 x i8], [30 x i8]* %3, i64 0, i64 0, !dbg !118
  call void @llvm.lifetime.start.p0i8(i64 30, i8* nonnull %23) #3, !dbg !118
  call void @llvm.dbg.declare(metadata [30 x i8]* %3, metadata !81, metadata !DIExpression()), !dbg !118
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* nonnull align 1 dereferenceable(30) %23, i8* nonnull align 1 dereferenceable(30) getelementptr inbounds ([30 x i8], [30 x i8]* @__const.xdp_dump_prog.____fmt, i64 0, i64 0), i64 30, i1 false), !dbg !118
  %24 = call i32 (i8*, i32, ...) inttoptr (i64 6 to i32 (i8*, i32, ...)*)(i8* nonnull %23, i32 30, i32 %20) #3, !dbg !118
  call void @llvm.lifetime.end.p0i8(i64 30, i8* nonnull %23) #3, !dbg !119
  br label %25, !dbg !120

25:                                               ; preds = %1, %22
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %10) #3, !dbg !121
  ret i32 2, !dbg !122
}

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg) #2

; Function Attrs: argmemonly nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #1

attributes #0 = { nounwind "correctly-rounded-divide-sqrt-fp-math"="false" "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="false" "stack-protector-buffer-size"="8" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nounwind readnone speculatable willreturn }
attributes #2 = { argmemonly nounwind willreturn }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!58, !59, !60}
!llvm.ident = !{!61}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "perf_map", scope: !2, file: !3, line: 12, type: !50, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "clang version 10.0.0-4ubuntu1 ", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !14, globals: !22, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "xdp-generated-dump.c", directory: "/home/vagrant/MocTok/xdmump")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 3150, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0, isUnsigned: true)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1, isUnsigned: true)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2, isUnsigned: true)
!12 = !DIEnumerator(name: "XDP_TX", value: 3, isUnsigned: true)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4, isUnsigned: true)
!14 = !{!15, !16, !17, !20}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!16 = !DIBasicType(name: "long int", size: 64, encoding: DW_ATE_signed)
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !18, line: 24, baseType: !19)
!18 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "")
!19 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!20 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !18, line: 31, baseType: !21)
!21 = !DIBasicType(name: "long long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!22 = !{!0, !23, !29, !35, !42}
!23 = !DIGlobalVariableExpression(var: !24, expr: !DIExpression())
!24 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 45, type: !25, isLocal: false, isDefinition: true)
!25 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 32, elements: !27)
!26 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!27 = !{!28}
!28 = !DISubrange(count: 4)
!29 = !DIGlobalVariableExpression(var: !30, expr: !DIExpression())
!30 = distinct !DIGlobalVariable(name: "__packed", scope: !2, file: !3, line: 10, type: !31, isLocal: false, isDefinition: true)
!31 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "S", file: !3, line: 7, size: 32, elements: !32)
!32 = !{!33, !34}
!33 = !DIDerivedType(tag: DW_TAG_member, name: "cookie", scope: !31, file: !3, line: 8, baseType: !17, size: 16)
!34 = !DIDerivedType(tag: DW_TAG_member, name: "pkt_len", scope: !31, file: !3, line: 9, baseType: !17, size: 16, offset: 16)
!35 = !DIGlobalVariableExpression(var: !36, expr: !DIExpression())
!36 = distinct !DIGlobalVariable(name: "bpf_perf_event_output", scope: !2, file: !37, line: 666, type: !38, isLocal: true, isDefinition: true)
!37 = !DIFile(filename: "../deps/include/bpf/bpf_helper_defs.h", directory: "/home/vagrant/MocTok/xdmump")
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DISubroutineType(types: !40)
!40 = !{!41, !15, !15, !20, !15, !20}
!41 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!42 = !DIGlobalVariableExpression(var: !43, expr: !DIExpression())
!43 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !37, line: 152, type: !44, isLocal: true, isDefinition: true)
!44 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !45, size: 64)
!45 = !DISubroutineType(types: !46)
!46 = !{!41, !47, !49, null}
!47 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !48, size: 64)
!48 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !26)
!49 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !18, line: 27, baseType: !7)
!50 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_map_def", file: !51, line: 33, size: 160, elements: !52)
!51 = !DIFile(filename: "../deps/include/bpf/bpf_helpers.h", directory: "/home/vagrant/MocTok/xdmump")
!52 = !{!53, !54, !55, !56, !57}
!53 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !50, file: !51, line: 34, baseType: !7, size: 32)
!54 = !DIDerivedType(tag: DW_TAG_member, name: "key_size", scope: !50, file: !51, line: 35, baseType: !7, size: 32, offset: 32)
!55 = !DIDerivedType(tag: DW_TAG_member, name: "value_size", scope: !50, file: !51, line: 36, baseType: !7, size: 32, offset: 64)
!56 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !50, file: !51, line: 37, baseType: !7, size: 32, offset: 96)
!57 = !DIDerivedType(tag: DW_TAG_member, name: "map_flags", scope: !50, file: !51, line: 38, baseType: !7, size: 32, offset: 128)
!58 = !{i32 7, !"Dwarf Version", i32 4}
!59 = !{i32 2, !"Debug Info Version", i32 3}
!60 = !{i32 1, !"wchar_size", i32 4}
!61 = !{!"clang version 10.0.0-4ubuntu1 "}
!62 = distinct !DISubprogram(name: "xdp_dump_prog", scope: !3, file: !3, line: 20, type: !63, scopeLine: 20, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !73)
!63 = !DISubroutineType(types: !64)
!64 = !{!41, !65}
!65 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!66 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 3161, size: 160, elements: !67)
!67 = !{!68, !69, !70, !71, !72}
!68 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !66, file: !6, line: 3162, baseType: !49, size: 32)
!69 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !66, file: !6, line: 3163, baseType: !49, size: 32, offset: 32)
!70 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !66, file: !6, line: 3164, baseType: !49, size: 32, offset: 64)
!71 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !66, file: !6, line: 3166, baseType: !49, size: 32, offset: 96)
!72 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !66, file: !6, line: 3167, baseType: !49, size: 32, offset: 128)
!73 = !{!74, !75, !76, !77, !78, !79, !80, !81}
!74 = !DILocalVariable(name: "ctx", arg: 1, scope: !62, file: !3, line: 20, type: !65)
!75 = !DILocalVariable(name: "data_end", scope: !62, file: !3, line: 21, type: !15)
!76 = !DILocalVariable(name: "data", scope: !62, file: !3, line: 22, type: !15)
!77 = !DILocalVariable(name: "flags", scope: !62, file: !3, line: 24, type: !20)
!78 = !DILocalVariable(name: "sample_size", scope: !62, file: !3, line: 25, type: !17)
!79 = !DILocalVariable(name: "ret", scope: !62, file: !3, line: 26, type: !41)
!80 = !DILocalVariable(name: "metadata", scope: !62, file: !3, line: 27, type: !31)
!81 = !DILocalVariable(name: "____fmt", scope: !82, file: !3, line: 39, type: !85)
!82 = distinct !DILexicalBlock(scope: !83, file: !3, line: 39, column: 5)
!83 = distinct !DILexicalBlock(scope: !84, file: !3, line: 38, column: 12)
!84 = distinct !DILexicalBlock(scope: !62, file: !3, line: 38, column: 7)
!85 = !DICompositeType(tag: DW_TAG_array_type, baseType: !26, size: 240, elements: !86)
!86 = !{!87}
!87 = !DISubrange(count: 30)
!88 = !DILocation(line: 0, scope: !62)
!89 = !DILocation(line: 21, column: 38, scope: !62)
!90 = !{!91, !92, i64 4}
!91 = !{!"xdp_md", !92, i64 0, !92, i64 4, !92, i64 8, !92, i64 12, !92, i64 16}
!92 = !{!"int", !93, i64 0}
!93 = !{!"omnipotent char", !94, i64 0}
!94 = !{!"Simple C/C++ TBAA"}
!95 = !DILocation(line: 21, column: 27, scope: !62)
!96 = !DILocation(line: 22, column: 34, scope: !62)
!97 = !{!91, !92, i64 0}
!98 = !DILocation(line: 22, column: 23, scope: !62)
!99 = !DILocation(line: 27, column: 3, scope: !62)
!100 = !DILocation(line: 27, column: 12, scope: !62)
!101 = !DILocation(line: 29, column: 12, scope: !62)
!102 = !DILocation(line: 29, column: 19, scope: !62)
!103 = !{!104, !105, i64 0}
!104 = !{!"S", !105, i64 0, !105, i64 2}
!105 = !{!"short", !93, i64 0}
!106 = !DILocation(line: 30, column: 39, scope: !62)
!107 = !DILocation(line: 30, column: 12, scope: !62)
!108 = !DILocation(line: 30, column: 20, scope: !62)
!109 = !{!104, !105, i64 2}
!110 = !DILocation(line: 32, column: 7, scope: !62)
!111 = !DILocation(line: 34, column: 12, scope: !62)
!112 = !DILocation(line: 34, column: 31, scope: !62)
!113 = !DILocation(line: 34, column: 9, scope: !62)
!114 = !DILocation(line: 37, column: 29, scope: !62)
!115 = !DILocation(line: 37, column: 7, scope: !62)
!116 = !DILocation(line: 38, column: 7, scope: !84)
!117 = !DILocation(line: 38, column: 7, scope: !62)
!118 = !DILocation(line: 39, column: 5, scope: !82)
!119 = !DILocation(line: 39, column: 5, scope: !83)
!120 = !DILocation(line: 40, column: 3, scope: !83)
!121 = !DILocation(line: 43, column: 1, scope: !62)
!122 = !DILocation(line: 42, column: 3, scope: !62)
