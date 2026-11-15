PROGRAM prog0
  VAR
    contador AT %QW0 : UINT;
  END_VAR
  contador := contador + 1;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK tarea0(INTERVAL := T#10ms, PRIORITY := 0);
    PROGRAM inst0 WITH tarea0 : prog0;
  END_RESOURCE
END_CONFIGURATION
